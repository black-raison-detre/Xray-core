package tun

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/observatory"
	tunicmp "github.com/xtls/xray-core/proxy/tun/icmp"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestGVisorDelayedICMPEchoReplySmoke(t *testing.T) {
	const delay = 20 * time.Millisecond

	linkEndpoint := channel.New(1, 1500, "")
	ipStack, err := createStack(linkEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	handler := &Handler{
		ctx:    context.Background(),
		config: &Config{IcmpMode: IcmpMode_PROBE},
		observatory: &testObservatory{report: &observatory.ObservationResult{Status: []*observatory.OutboundStatus{
			{OutboundTag: "proxy", Alive: true, Delay: delay.Milliseconds()},
		}}},
	}
	gvisorStack := &stackGVisor{
		ctx:      handler.ctx,
		handler:  handler,
		stack:    ipStack,
		endpoint: linkEndpoint,
	}
	defer func() {
		handler.stopICMPEchoReplies()
		if err := gvisorStack.Close(); err != nil {
			t.Errorf("failed to close gVisor stack: %v", err)
		}
		linkEndpoint.Close()
	}()

	srcIP := tcpip.AddrFrom4([4]byte{10, 0, 0, 2})
	dstIP := tcpip.AddrFrom4([4]byte{1, 1, 1, 1})
	request := []byte{
		byte(header.ICMPv4Echo), 0,
		0, 0,
		0x12, 0x34,
		0x56, 0x78,
		0xaa, 0xbb,
	}
	if err := tunicmp.RewriteChecksum(header.IPv4ProtocolNumber, request, srcIP, dstIP); err != nil {
		t.Fatal(err)
	}
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(request)})
	defer packet.DecRef()

	started := time.Now()
	if !gvisorStack.handleICMPv4Packet(stack.TransportEndpointID{RemoteAddress: srcIP, LocalAddress: dstIP}, packet) {
		t.Fatal("expected ICMP request to be handled")
	}
	if immediate := linkEndpoint.Read(); immediate != nil {
		immediate.DecRef()
		t.Fatal("received ICMP reply before configured delay")
	}

	readCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	replyPacket := linkEndpoint.ReadContext(readCtx)
	if replyPacket == nil {
		t.Fatal("timed out waiting for delayed ICMP reply")
	}
	defer replyPacket.DecRef()
	if elapsed := time.Since(started); elapsed < delay {
		t.Fatalf("reply arrived after %s, want at least %s", elapsed, delay)
	}

	replyView := replyPacket.ToView()
	defer replyView.Release()
	replyBytes := replyView.AsSlice()
	if len(replyBytes) < header.IPv4MinimumSize+header.ICMPv4MinimumSize {
		t.Fatalf("short ICMP reply packet: %d bytes", len(replyBytes))
	}
	ipHeader := header.IPv4(replyBytes)
	if got := ipHeader.SourceAddress(); got != dstIP {
		t.Fatalf("reply source = %s, want %s", got, dstIP)
	}
	if got := ipHeader.DestinationAddress(); got != srcIP {
		t.Fatalf("reply destination = %s, want %s", got, srcIP)
	}
	icmpHeader := header.ICMPv4(replyBytes[header.IPv4MinimumSize:])
	if icmpHeader.Type() != header.ICMPv4EchoReply || icmpHeader.Ident() != 0x1234 || icmpHeader.Sequence() != 0x5678 {
		t.Fatalf("unexpected ICMP reply type/id/sequence: %d/%x/%x", icmpHeader.Type(), icmpHeader.Ident(), icmpHeader.Sequence())
	}
}

func TestGVisorProbeModeDropsWithoutObservation(t *testing.T) {
	linkEndpoint := channel.New(1, 1500, "")
	ipStack, err := createStack(linkEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	handler := &Handler{ctx: context.Background(), config: &Config{IcmpMode: IcmpMode_PROBE}}
	gvisorStack := &stackGVisor{ctx: handler.ctx, handler: handler, stack: ipStack, endpoint: linkEndpoint}
	defer func() {
		handler.stopICMPEchoReplies()
		if err := gvisorStack.Close(); err != nil {
			t.Errorf("failed to close gVisor stack: %v", err)
		}
		linkEndpoint.Close()
	}()

	request := []byte{byte(header.ICMPv4Echo), 0, 0, 0, 0x12, 0x34, 0x56, 0x78}
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(request)})
	defer packet.DecRef()
	gvisorStack.handleICMPv4Packet(stack.TransportEndpointID{
		RemoteAddress: tcpip.AddrFrom4([4]byte{10, 0, 0, 2}),
		LocalAddress:  tcpip.AddrFrom4([4]byte{1, 1, 1, 1}),
	}, packet)

	readCtx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if reply := linkEndpoint.ReadContext(readCtx); reply != nil {
		reply.DecRef()
		t.Fatal("unexpected ICMP reply without Observatory result")
	}
}

func TestGVisorShutdownSuppressesDelayedICMPEchoReply(t *testing.T) {
	const delay = 50 * time.Millisecond

	linkEndpoint := channel.New(1, 1500, "")
	ipStack, err := createStack(linkEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	handler := &Handler{
		ctx:    context.Background(),
		config: &Config{IcmpMode: IcmpMode_PROBE},
		observatory: &testObservatory{report: &observatory.ObservationResult{Status: []*observatory.OutboundStatus{
			{OutboundTag: "proxy", Alive: true, Delay: delay.Milliseconds()},
		}}},
	}
	gvisorStack := &stackGVisor{ctx: handler.ctx, handler: handler, stack: ipStack, endpoint: linkEndpoint}
	defer func() {
		handler.stopICMPEchoReplies()
		if err := gvisorStack.Close(); err != nil {
			t.Errorf("failed to close gVisor stack: %v", err)
		}
		linkEndpoint.Close()
	}()

	request := []byte{byte(header.ICMPv4Echo), 0, 0, 0, 0x12, 0x34, 0x56, 0x78}
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(request)})
	defer packet.DecRef()
	gvisorStack.handleICMPv4Packet(stack.TransportEndpointID{
		RemoteAddress: tcpip.AddrFrom4([4]byte{10, 0, 0, 2}),
		LocalAddress:  tcpip.AddrFrom4([4]byte{1, 1, 1, 1}),
	}, packet)
	handler.stopICMPEchoReplies()

	readCtx, cancel := context.WithTimeout(context.Background(), 2*delay)
	defer cancel()
	if reply := linkEndpoint.ReadContext(readCtx); reply != nil {
		reply.DecRef()
		t.Fatal("unexpected ICMP reply after handler shutdown")
	}
}
