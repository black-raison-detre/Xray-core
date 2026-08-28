package packetstack

import (
	"context"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	defaultNIC tcpip.NICID = 1

	tcpRXBufMinSize = tcp.MinBufferSize
	tcpRXBufDefSize = tcp.DefaultSendBufferSize
	tcpRXBufMaxSize = 8 << 20

	tcpTXBufMinSize = tcp.MinBufferSize
	tcpTXBufDefSize = tcp.DefaultReceiveBufferSize
	tcpTXBufMaxSize = 6 << 20

	maxICMPProbeDelay       = 30 * time.Second
	maxPendingICMPEchoReply = 256
)

type Options struct {
	Endpoint         stack.LinkEndpoint
	IdleTimeout      time.Duration
	HandleConnection func(net.Conn, net.Destination)
	ICMPEchoDelay    func() (time.Duration, bool)
	LogPrefix        string
}

type Stack struct {
	ctx             context.Context
	options         Options
	stack           *stack.Stack
	closeOnce       sync.Once
	icmpTimerAccess sync.Mutex
	icmpTimers      map[uint64]*time.Timer
	icmpNextTimerID uint64
	icmpReplyCount  int
	icmpClosing     bool
	icmpReplyWG     sync.WaitGroup
}

func New(ctx context.Context, options Options) (*Stack, error) {
	if options.Endpoint == nil {
		return nil, errors.New("packet stack endpoint is required")
	}
	if options.HandleConnection == nil {
		return nil, errors.New("packet stack connection handler is required")
	}
	if options.ICMPEchoDelay == nil {
		options.ICMPEchoDelay = func() (time.Duration, bool) { return 0, true }
	}
	if options.LogPrefix == "" {
		options.LogPrefix = "packetstack"
	}
	return &Stack{ctx: ctx, options: options}, nil
}

func (s *Stack) Start() error {
	ipStack, err := createStack(s.options.Endpoint)
	if err != nil {
		return err
	}
	tcpForwarder := tcp.NewForwarder(ipStack, 0, 65535, func(r *tcp.ForwarderRequest) {
		go func() {
			var wq waiter.Queue
			id := r.ID()
			ep, err := r.CreateEndpoint(&wq)
			if err != nil {
				errors.LogError(s.ctx, err.String())
				r.Complete(true)
				return
			}
			defer func() {
				ep.Close()
				r.Complete(false)
			}()
			options := ep.SocketOptions()
			options.SetKeepAlive(false)
			options.SetReuseAddress(true)
			options.SetReusePort(true)
			s.options.HandleConnection(gonet.NewTCPConn(&wq, ep), net.TCPDestination(net.IPAddress(id.LocalAddress.AsSlice()), net.Port(id.LocalPort)))
		}()
	})
	ipStack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	udpForwarder := newUDPConnectionHandler(s.options.HandleConnection, s.writeRawUDPPacket)
	ipStack.SetTransportProtocolHandler(udp.ProtocolNumber, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		cloned := pkt.Clone()
		data := cloned.Data().AsRange().ToSlice()
		cloned.DecRef()
		srcIP := net.IPAddress(id.RemoteAddress.AsSlice())
		dstIP := net.IPAddress(id.LocalAddress.AsSlice())
		if srcIP == nil || dstIP == nil {
			return true
		}
		udpForwarder.HandlePacket(net.UDPDestination(srcIP, net.Port(id.RemotePort)), net.UDPDestination(dstIP, net.Port(id.LocalPort)), data)
		return true
	})
	ipStack.SetTransportProtocolHandler(icmp.ProtocolNumber4, s.handleICMPv4Packet)
	ipStack.SetTransportProtocolHandler(icmp.ProtocolNumber6, s.handleICMPv6Packet)
	s.stack = ipStack
	return nil
}

func (s *Stack) writeRawUDPPacket(payload []byte, src, dst net.Destination) error {
	udpLen := header.UDPMinimumSize + len(payload)
	srcIP := tcpip.AddrFromSlice(src.Address.IP())
	dstIP := tcpip.AddrFromSlice(dst.Address.IP())
	ipHeaderSize := header.IPv6MinimumSize
	ipProtocol := header.IPv6ProtocolNumber
	if dst.Address.Family().IsIPv4() {
		ipHeaderSize = header.IPv4MinimumSize
		ipProtocol = header.IPv4ProtocolNumber
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{ReserveHeaderBytes: ipHeaderSize + header.UDPMinimumSize, Payload: buffer.MakeWithData(payload)})
	defer pkt.DecRef()
	udpHeader := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
	udpHeader.Encode(&header.UDPFields{SrcPort: uint16(src.Port), DstPort: uint16(dst.Port), Length: uint16(udpLen)})
	udpHeader.SetChecksum(calculateUDPChecksum(udpHeader, payload, srcIP, dstIP))
	if ipProtocol == header.IPv4ProtocolNumber {
		ipHeader := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
		ipHeader.Encode(&header.IPv4Fields{TotalLength: uint16(header.IPv4MinimumSize + udpLen), TTL: 64, Protocol: uint8(header.UDPProtocolNumber), SrcAddr: srcIP, DstAddr: dstIP})
		ipHeader.SetChecksum(^ipHeader.CalculateChecksum())
	} else {
		ipHeader := header.IPv6(pkt.NetworkHeader().Push(header.IPv6MinimumSize))
		ipHeader.Encode(&header.IPv6Fields{PayloadLength: uint16(udpLen), TransportProtocol: header.UDPProtocolNumber, HopLimit: 64, SrcAddr: srcIP, DstAddr: dstIP})
	}
	if err := s.stack.WriteRawPacket(defaultNIC, ipProtocol, buffer.MakeWithView(pkt.ToView())); err != nil {
		return errors.New("failed to write raw udp packet back to stack", err)
	}
	return nil
}

func calculateUDPChecksum(udpHeader header.UDP, payload []byte, srcIP, dstIP tcpip.Address) uint16 {
	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, srcIP, dstIP, udpHeader.Length())
	xsum = ^udpHeader.CalculateChecksum(checksum.Checksum(payload, xsum))
	if xsum == 0 {
		return 0xffff
	}
	return xsum
}

func (s *Stack) Close() error {
	s.closeOnce.Do(func() {
		s.stopICMPEchoReplies()
		if s.stack == nil {
			return
		}
		s.options.Endpoint.Attach(nil)
		s.stack.Close()
		for _, endpoint := range s.stack.CleanupEndpoints() {
			endpoint.Abort()
		}
	})
	return nil
}

func createStack(endpoint stack.LinkEndpoint) (*stack.Stack, error) {
	ipStack := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6}, HandleLocal: false})
	if err := ipStack.CreateNIC(defaultNIC, endpoint); err != nil {
		return nil, errors.New(err.String())
	}
	ipStack.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: defaultNIC}, {Destination: header.IPv6EmptySubnet, NIC: defaultNIC}})
	if err := ipStack.SetSpoofing(defaultNIC, true); err != nil {
		return nil, errors.New(err.String())
	}
	if err := ipStack.SetPromiscuousMode(defaultNIC, true); err != nil {
		return nil, errors.New(err.String())
	}
	cOpt := tcpip.CongestionControlOption("cubic")
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &cOpt)
	sOpt := tcpip.TCPSACKEnabled(true)
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &sOpt)
	mOpt := tcpip.TCPModerateReceiveBufferOption(true)
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &mOpt)
	rOpt := tcpip.TCPRecovery(0)
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &rOpt)
	rx := tcpip.TCPReceiveBufferSizeRangeOption{Min: tcpRXBufMinSize, Default: tcpRXBufDefSize, Max: tcpRXBufMaxSize}
	if err := ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &rx); err != nil {
		return nil, errors.New(err.String())
	}
	tx := tcpip.TCPSendBufferSizeRangeOption{Min: tcpTXBufMinSize, Default: tcpTXBufDefSize, Max: tcpTXBufMaxSize}
	if err := ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &tx); err != nil {
		return nil, errors.New(err.String())
	}
	return ipStack, nil
}
