package packetstack

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	packeticmp "github.com/xtls/xray-core/proxy/tun/icmp"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestDelayedICMPEchoReply(t *testing.T) {
	const delay = 20 * time.Millisecond
	endpoint := channel.New(1, 1500, "")
	s, err := New(context.Background(), Options{
		Endpoint:         endpoint,
		HandleConnection: func(net.Conn, net.Destination) {},
		ICMPEchoDelay:    func() (time.Duration, bool) { return delay, true },
		LogPrefix:        "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close(); endpoint.Close() }()

	srcIP := tcpip.AddrFrom4([4]byte{10, 0, 0, 2})
	dstIP := tcpip.AddrFrom4([4]byte{1, 1, 1, 1})
	request := []byte{byte(header.ICMPv4Echo), 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 0xaa, 0xbb}
	if err := packeticmp.RewriteChecksum(header.IPv4ProtocolNumber, request, srcIP, dstIP); err != nil {
		t.Fatal(err)
	}
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(request)})
	defer packet.DecRef()
	started := time.Now()
	if !s.handleICMPv4Packet(stack.TransportEndpointID{RemoteAddress: srcIP, LocalAddress: dstIP}, packet) {
		t.Fatal("request was not handled")
	}
	if immediate := endpoint.Read(); immediate != nil {
		immediate.DecRef()
		t.Fatal("reply arrived before delay")
	}
	readCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	reply := endpoint.ReadContext(readCtx)
	if reply == nil {
		t.Fatal("timed out waiting for reply")
	}
	defer reply.DecRef()
	if time.Since(started) < delay {
		t.Fatal("reply arrived before configured delay")
	}
	view := reply.ToView()
	defer view.Release()
	bytes := view.AsSlice()
	if len(bytes) < header.IPv4MinimumSize+header.ICMPv4MinimumSize {
		t.Fatalf("short reply: %d", len(bytes))
	}
	ipHeader := header.IPv4(bytes)
	if ipHeader.SourceAddress() != dstIP || ipHeader.DestinationAddress() != srcIP {
		t.Fatal("reply endpoints were not reversed")
	}
	icmpHeader := header.ICMPv4(bytes[header.IPv4MinimumSize:])
	if icmpHeader.Type() != header.ICMPv4EchoReply || icmpHeader.Ident() != 0x1234 || icmpHeader.Sequence() != 0x5678 {
		t.Fatal("unexpected ICMP reply")
	}
}

func TestProbeModeDropsWithoutObservation(t *testing.T) {
	endpoint := channel.New(1, 1500, "")
	s, err := New(context.Background(), Options{Endpoint: endpoint, HandleConnection: func(net.Conn, net.Destination) {}, ICMPEchoDelay: func() (time.Duration, bool) { return 0, false }})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close(); endpoint.Close() }()
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte{byte(header.ICMPv4Echo), 0, 0, 0, 0x12, 0x34, 0x56, 0x78})})
	defer packet.DecRef()
	s.handleICMPv4Packet(stack.TransportEndpointID{RemoteAddress: tcpip.AddrFrom4([4]byte{10, 0, 0, 2}), LocalAddress: tcpip.AddrFrom4([4]byte{1, 1, 1, 1})}, packet)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if reply := endpoint.ReadContext(ctx); reply != nil {
		reply.DecRef()
		t.Fatal("unexpected reply")
	}
}

func TestSchedulerBoundsAndCloseDrains(t *testing.T) {
	s := &Stack{}
	started := make(chan struct{})
	release := make(chan struct{})
	if !s.scheduleICMPEchoReply(time.Millisecond, func() { close(started); <-release }) {
		t.Fatal("schedule failed")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("callback did not start")
	}
	for range maxPendingICMPEchoReply - 1 {
		if !s.scheduleICMPEchoReply(maxICMPProbeDelay, func() {}) {
			t.Fatal("pending limit too small")
		}
	}
	if s.scheduleICMPEchoReply(maxICMPProbeDelay, func() {}) {
		t.Fatal("pending limit was not enforced")
	}
	stopped := make(chan struct{})
	go func() { s.stopICMPEchoReplies(); close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("shutdown returned during callback")
	case <-time.After(10 * time.Millisecond):
	}
	close(release)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not drain")
	}
	if s.scheduleICMPEchoReply(time.Millisecond, func() {}) {
		t.Fatal("scheduler accepted work after close")
	}
}
