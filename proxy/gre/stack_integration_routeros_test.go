//go:build routeros_gre

package gre

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/tun"
	"github.com/xtls/xray-core/transport"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func TestGREInMemoryTCPAndUDPFlow(t *testing.T) {
	config := testRuntimeConfig(t)
	tests := []struct {
		name            string
		clientAddress   tcpip.Address
		targetAddress   tcpip.Address
		networkProtocol tcpip.NetworkProtocolNumber
		defaultSubnet   tcpip.Subnet
	}{
		{
			name:            "ipv4",
			clientAddress:   tcpip.AddrFrom4(config.allowed[0].Addr().As4()),
			targetAddress:   tcpip.AddrFrom4([4]byte{198, 51, 100, 10}),
			networkProtocol: ipv4.ProtocolNumber,
			defaultSubnet:   header.IPv4EmptySubnet,
		},
		{
			name:            "ipv6",
			clientAddress:   tcpip.AddrFrom16(config.allowed[1].Addr().As16()),
			targetAddress:   tcpip.AddrFrom16(netip.MustParseAddr("2001:db8:198:51::10").As16()),
			networkProtocol: ipv6.ProtocolNumber,
			defaultSubnet:   header.IPv6EmptySubnet,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			testGREInMemoryTCPAndUDPFlow(t, config, test.clientAddress, test.targetAddress, test.networkProtocol, test.defaultSubnet)
		})
	}
}

func testGREInMemoryTCPAndUDPFlow(t *testing.T, config runtimeConfig, clientAddress, targetAddress tcpip.Address, networkProtocol tcpip.NetworkProtocolNumber, defaultSubnet tcpip.Subnet) {
	t.Helper()
	targetDevice := newMemoryPacketDevice()

	requestLog := make(chan string, 3)
	dispatchDone := make(chan struct{}, 3)
	uplink, downlink := new(appstats.Counter), new(appstats.Counter)
	handler := &Handler{
		ctx: context.Background(), config: &Config{UserLevel: 7}, tag: "gre-test",
		sniffingRequest: session.SniffingRequest{Enabled: true},
		uplinkCounter:   uplink, downlinkCounter: downlink,
		dispatcher: &testGREDispatcher{dispatch: func(ctx context.Context, destination xnet.Destination, link *transport.Link) error {
			defer func() { dispatchDone <- struct{}{} }()
			inbound := session.InboundFromContext(ctx)
			content := session.ContentFromContext(ctx)
			if inbound == nil || inbound.Name != "gre" || inbound.Tag != "gre-test" || inbound.User == nil || inbound.User.Level != 7 || inbound.Source.Address == nil || !bytes.Equal(inbound.Source.Address.IP(), clientAddress.AsSlice()) || content == nil || !content.SniffingRequest.Enabled {
				requestLog <- "invalid inbound metadata"
				return fmt.Errorf("invalid inbound metadata")
			}
			switch destination.Port {
			case 443:
				reader := &buf.BufferedReader{Reader: link.Reader}
				defer reader.Close()
				payload := make([]byte, len("tcp-ping"))
				if _, err := io.ReadFull(reader, payload); err != nil {
					requestLog <- "tcp-read:" + err.Error()
					return err
				}
				requestLog <- string(payload)
				response := buf.New()
				response.Write([]byte("tcp-pong"))
				return link.Writer.WriteMultiBuffer(buf.MultiBuffer{response})
			case 53:
				payload, err := link.Reader.ReadMultiBuffer()
				if err != nil {
					buf.ReleaseMulti(payload)
					requestLog <- "udp-read:" + err.Error()
					return err
				}
				requestLog <- fmt.Sprintf("udp:%d", payload.Len())
				return link.Writer.WriteMultiBuffer(payload)
			}
			return fmt.Errorf("unexpected destination: %v", destination)
		}},
	}
	targetStack, err := tun.NewStack(context.Background(), tun.StackOptions{
		Tun: targetDevice, MTU: config.mtu, Remote: true,
	}, handler)
	if err != nil {
		t.Fatal(err)
	}
	if err := targetStack.Start(); err != nil {
		t.Fatal(err)
	}

	clientMTU := config.mtu
	if networkProtocol == ipv6.ProtocolNumber {
		clientMTU -= 8 // room for the experiment extension added by the bridge
	}
	clientEndpoint := channel.New(1024, clientMTU, "")
	clientStack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if err := clientStack.CreateNIC(1, clientEndpoint); err != nil {
		t.Fatal(err.String())
	}
	if err := clientStack.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          networkProtocol,
		AddressWithPrefix: clientAddress.WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		t.Fatal(err.String())
	}
	clientStack.SetRouteTable([]tcpip.Route{{Destination: defaultSubnet, NIC: 1}})

	bridgeCtx, cancelBridge := context.WithCancel(context.Background())
	var bridgeWG sync.WaitGroup
	var ingressPackets atomic.Int64
	var egressPackets atomic.Int64
	bridgeWG.Add(2)
	go func() {
		defer bridgeWG.Done()
		for {
			packet := clientEndpoint.ReadContext(bridgeCtx)
			if packet == nil {
				return
			}
			view := packet.ToView()
			packet.DecRef()
			inner := append([]byte(nil), view.AsSlice()...)
			view.Release()
			if networkProtocol == ipv6.ProtocolNumber {
				// GRE accepted experimental IPv6 extension headers before this
				// port; exercise them on real TCP/UDP traffic, including fragments.
				inner = testIPv6ExtensionHeader(inner, 253)
			}
			datagram := testOuterGRE(config, inner, false, 0)
			decoded, err := decodeGREDatagram(datagram, config)
			if err != nil {
				continue
			}
			ingressPackets.Add(1)
			select {
			case targetDevice.input <- append([]byte(nil), decoded.innerPacket...):
			case <-bridgeCtx.Done():
				return
			}
		}
	}()
	go func() {
		defer bridgeWG.Done()
		for {
			var packet []byte
			select {
			case packet = <-targetDevice.output:
			case <-bridgeCtx.Done():
				return
			}
			// NewStack must emit packets that already fit the tunnel MTU.
			encoded, err := encodeGREPacket(packet, config.mtu)
			if err != nil {
				requestLog <- "egress:" + err.Error()
				return
			}
			egressPackets.Add(1)
			inbound := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(encoded[4:])})
			clientEndpoint.InjectInbound(networkProtocolForPacket(packet), inbound)
			inbound.DecRef()
		}
	}()

	cleanup := func() {
		cancelBridge()
		bridgeWG.Wait()
		_ = targetDevice.Close()
		_ = targetStack.Close()
		clientStack.Close()
		for _, endpoint := range clientStack.CleanupEndpoints() {
			endpoint.Abort()
		}
		clientEndpoint.Close()
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tcpConn, err := gonet.DialContextTCP(ctx, clientStack, tcpip.FullAddress{NIC: 1, Addr: targetAddress, Port: 443}, networkProtocol)
	if err != nil {
		t.Fatal(err)
	}
	_ = tcpConn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := tcpConn.Write([]byte("tcp-ping")); err != nil {
		t.Fatal(err)
	}
	tcpReply := make([]byte, len("tcp-pong"))
	if _, err := io.ReadFull(tcpConn, tcpReply); err != nil {
		t.Fatal(err)
	}
	_ = tcpConn.Close()
	if string(tcpReply) != "tcp-pong" {
		t.Fatalf("TCP reply = %q", tcpReply)
	}

	for index, size := range []int{8, 4096} {
		udpConn, err := gonet.DialUDP(
			clientStack,
			&tcpip.FullAddress{NIC: 1, Addr: clientAddress, Port: uint16(53000 + index)},
			&tcpip.FullAddress{NIC: 1, Addr: targetAddress, Port: 53},
			networkProtocol,
		)
		if err != nil {
			t.Fatal(err)
		}
		_ = udpConn.SetDeadline(time.Now().Add(5 * time.Second))
		payload := bytes.Repeat([]byte{byte(size)}, size)
		if _, err := udpConn.Write(payload); err != nil {
			t.Fatal(err)
		}
		udpReply := make([]byte, len(payload))
		if _, err := io.ReadFull(udpConn, udpReply); err != nil {
			t.Fatal(err)
		}
		_ = udpConn.Close()
		if !bytes.Equal(udpReply, payload) {
			t.Fatalf("UDP %d-byte reply mismatch", size)
		}
	}

	seen := map[string]bool{}
	for range 3 {
		select {
		case request := <-requestLog:
			seen[request] = true
		case <-ctx.Done():
			t.Fatal("timed out waiting for dispatcher-side requests")
		}
	}
	if !seen["tcp-ping"] || !seen["udp:8"] || !seen["udp:4096"] {
		t.Fatalf("dispatcher-side requests = %#v", seen)
	}
	for range 3 {
		select {
		case <-dispatchDone:
		case <-ctx.Done():
			t.Fatal("dispatcher did not finish")
		}
	}
	const expectedBytes = int64(len("tcp-ping") + 8 + 4096)
	if uplink.Value() != expectedBytes || downlink.Value() != expectedBytes {
		t.Fatalf("traffic counters uplink=%d downlink=%d want=%d", uplink.Value(), downlink.Value(), expectedBytes)
	}
	if ingressPackets.Load() == 0 || egressPackets.Load() == 0 {
		t.Fatalf("GRE packet counters ingress=%d egress=%d", ingressPackets.Load(), egressPackets.Load())
	}
}

func networkProtocolForPacket(packet []byte) tcpip.NetworkProtocolNumber {
	if len(packet) > 0 && packet[0]>>4 == 6 {
		return header.IPv6ProtocolNumber
	}
	return header.IPv4ProtocolNumber
}

// The simulated router retains gVisor as an independent peer; the GRE side uses
// exactly the same packet interface as the raw Linux device and the shared stack.
type memoryPacketDevice struct {
	input, output chan []byte
	closed        chan struct{}
	once          sync.Once
}

func newMemoryPacketDevice() *memoryPacketDevice {
	return &memoryPacketDevice{input: make(chan []byte, 32), output: make(chan []byte, 32), closed: make(chan struct{})}
}
func (*memoryPacketDevice) Start() error          { return nil }
func (*memoryPacketDevice) Name() (string, error) { return "gre-test", nil }
func (*memoryPacketDevice) Index() (int, error)   { return 0, nil }
func (d *memoryPacketDevice) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}

func (d *memoryPacketDevice) ReadPacket(b []byte) ([]byte, error) {
	select {
	case p := <-d.input:
		return b[:copy(b, p)], nil
	case <-d.closed:
		return nil, io.ErrClosedPipe
	}
}

func (d *memoryPacketDevice) WritePacket(header, payload []byte) error {
	p := append(append([]byte(nil), header...), payload...)
	select {
	case d.output <- p:
		return nil
	case <-d.closed:
		return io.ErrClosedPipe
	}
}

type testConnectionHandler func(xnet.Conn, xnet.Destination)

func (h testConnectionHandler) HandleConnection(c xnet.Conn, d xnet.Destination) { h(c, d) }

func TestGRESharedStackFragmentableIPv6Options(t *testing.T) {
	config := testRuntimeConfig(t)
	device := newMemoryPacketDevice()
	s, err := tun.NewStack(context.Background(), tun.StackOptions{Tun: device, MTU: config.mtu, Remote: true}, testConnectionHandler(func(c xnet.Conn, _ xnet.Destination) { c.Close() }))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer device.Close()
	// Destination options belong to the fragmentable part of the packet. The
	// second fragment can arrive first and contains none of those options.
	request := testIPv6ExtensionHeader(testICMPEchoRequest(true), 60)
	for _, part := range [][2]int{{8, len(request) - 40}, {0, 8}} {
		fragment := make([]byte, 48+part[1]-part[0])
		copy(fragment, request[:40])
		fragment[6], fragment[40] = 44, request[6]
		binary.BigEndian.PutUint16(fragment[4:6], uint16(len(fragment)-40))
		field := uint16(part[0])
		if part[0] == 0 {
			field |= 1
		}
		binary.BigEndian.PutUint16(fragment[42:44], field)
		binary.BigEndian.PutUint32(fragment[44:48], 12345)
		copy(fragment[48:], request[40+part[0]:40+part[1]])
		decoded, err := decodeGREDatagram(testOuterGRE(config, fragment, false, 0), config)
		if err != nil {
			t.Fatal(err)
		}
		s.Input(decoded.innerPacket)
	}
	select {
	case reply := <-device.output:
		if len(reply) != 51 || reply[40] != 129 || testICMPChecksum(reply) != 0 {
			t.Fatalf("invalid echo response: %x", reply)
		}
	case <-time.After(time.Second):
		t.Fatal("fragmented ICMPv6 echo with destination options was not reassembled")
	}
}

type testGREDispatcher struct {
	routing.Dispatcher
	dispatch func(context.Context, xnet.Destination, *transport.Link) error
}

func (d *testGREDispatcher) DispatchLink(ctx context.Context, destination xnet.Destination, link *transport.Link) error {
	return d.dispatch(ctx, destination, link)
}
