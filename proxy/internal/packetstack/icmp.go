package packetstack

import (
	"time"

	"github.com/xtls/xray-core/common/errors"
	packeticmp "github.com/xtls/xray-core/proxy/tun/icmp"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func (s *Stack) handleICMPv4Packet(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	return s.handleICMPEchoPacket(header.IPv4ProtocolNumber, id, pkt)
}

func (s *Stack) handleICMPv6Packet(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	return s.handleICMPEchoPacket(header.IPv6ProtocolNumber, id, pkt)
}

func (s *Stack) handleICMPEchoPacket(netProto tcpip.NetworkProtocolNumber, id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	srcIP, dstIP := id.RemoteAddress, id.LocalAddress
	if srcIP.Len() == 0 || dstIP.Len() == 0 {
		return true
	}
	message := transportPacketBytes(pkt)
	ident, sequence, ok := packeticmp.ParseEchoRequest(netProto, message)
	if !ok {
		return true
	}
	reply, err := packeticmp.BuildLocalEchoReply(netProto, message, dstIP, srcIP)
	if err != nil {
		errors.LogInfoInner(s.ctx, err, "[", s.options.LogPrefix, "] failed to build local icmp echo reply")
		return true
	}
	delay, available := s.options.ICMPEchoDelay()
	if !available {
		errors.LogDebug(s.ctx, "[", s.options.LogPrefix, "][icmp] probe result unavailable; dropping echo request")
		return true
	}
	writeReply := func() {
		errors.LogDebug(s.ctx, "[", s.options.LogPrefix, "][icmp] ", packeticmp.ProtocolLabel(netProto), " echo reply ", dstIP, " -> ", srcIP, " delay=", delay, " id=", ident, " seq=", sequence)
		if err := s.writeRawICMPPacket(netProto, reply, dstIP, srcIP); err != nil {
			errors.LogInfoInner(s.ctx, err, "[", s.options.LogPrefix, "] failed to write local icmp echo reply")
		}
	}
	if delay <= 0 {
		writeReply()
	} else if !s.scheduleICMPEchoReply(delay, writeReply) {
		errors.LogDebug(s.ctx, "[", s.options.LogPrefix, "][icmp] delayed reply queue unavailable; dropping echo request")
	}
	return true
}

func (s *Stack) writeRawICMPPacket(netProto tcpip.NetworkProtocolNumber, message []byte, srcIP, dstIP tcpip.Address) error {
	ipHeaderSize, ipProtocol, transportProtocol := header.IPv6MinimumSize, header.IPv6ProtocolNumber, header.ICMPv6ProtocolNumber
	if netProto == header.IPv4ProtocolNumber {
		ipHeaderSize, ipProtocol, transportProtocol = header.IPv4MinimumSize, header.IPv4ProtocolNumber, header.ICMPv4ProtocolNumber
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{ReserveHeaderBytes: ipHeaderSize, Payload: buffer.MakeWithData(message)})
	defer pkt.DecRef()
	if netProto == header.IPv4ProtocolNumber {
		ipHeader := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
		ipHeader.Encode(&header.IPv4Fields{TotalLength: uint16(header.IPv4MinimumSize + len(message)), TTL: 64, Protocol: uint8(transportProtocol), SrcAddr: srcIP, DstAddr: dstIP})
		ipHeader.SetChecksum(^ipHeader.CalculateChecksum())
	} else {
		ipHeader := header.IPv6(pkt.NetworkHeader().Push(header.IPv6MinimumSize))
		ipHeader.Encode(&header.IPv6Fields{PayloadLength: uint16(len(message)), TransportProtocol: transportProtocol, HopLimit: 64, SrcAddr: srcIP, DstAddr: dstIP})
	}
	if err := s.stack.WriteRawPacket(defaultNIC, ipProtocol, buffer.MakeWithView(pkt.ToView())); err != nil {
		return errors.New("failed to write raw icmp packet back to stack", err)
	}
	return nil
}

func (s *Stack) scheduleICMPEchoReply(delay time.Duration, reply func()) bool {
	if delay <= 0 || delay > maxICMPProbeDelay || reply == nil {
		return false
	}
	s.icmpTimerAccess.Lock()
	defer s.icmpTimerAccess.Unlock()
	if s.icmpClosing || s.icmpReplyCount >= maxPendingICMPEchoReply {
		return false
	}
	if s.icmpTimers == nil {
		s.icmpTimers = make(map[uint64]*time.Timer)
	}
	s.icmpNextTimerID++
	timerID := s.icmpNextTimerID
	s.icmpReplyCount++
	s.icmpTimers[timerID] = time.AfterFunc(delay, func() {
		s.icmpTimerAccess.Lock()
		delete(s.icmpTimers, timerID)
		if s.icmpClosing {
			s.icmpReplyCount--
			s.icmpTimerAccess.Unlock()
			return
		}
		s.icmpReplyWG.Add(1)
		s.icmpTimerAccess.Unlock()
		defer func() { s.icmpTimerAccess.Lock(); s.icmpReplyCount--; s.icmpTimerAccess.Unlock(); s.icmpReplyWG.Done() }()
		reply()
	})
	return true
}

func (s *Stack) stopICMPEchoReplies() {
	s.icmpTimerAccess.Lock()
	s.icmpClosing = true
	for timerID, timer := range s.icmpTimers {
		if timer.Stop() {
			s.icmpReplyCount--
		}
		delete(s.icmpTimers, timerID)
	}
	s.icmpTimerAccess.Unlock()
	s.icmpReplyWG.Wait()
}

func transportPacketBytes(pkt *stack.PacketBuffer) []byte {
	headerBytes := pkt.TransportHeader().Slice()
	payloadBytes := pkt.Data().AsRange().ToSlice()
	message := make([]byte, len(headerBytes)+len(payloadBytes))
	copy(message, headerBytes)
	copy(message[len(headerBytes):], payloadBytes)
	return message
}
