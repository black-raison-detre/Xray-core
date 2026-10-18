//go:build routeros_gre

package gre

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/internal/packetstack"
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
	targetEndpoint := channel.New(1024, config.mtu, "")

	requestLog := make(chan string, 3)
	targetStack, err := packetstack.New(context.Background(), packetstack.Options{
		Endpoint: targetEndpoint,
		HandleConnection: func(conn xnet.Conn, destination xnet.Destination) {
			defer conn.Close()
			switch destination.Port {
			case 443:
				payload := make([]byte, len("tcp-ping"))
				if _, err := io.ReadFull(conn, payload); err != nil {
					requestLog <- "tcp-read:" + err.Error()
					return
				}
				requestLog <- string(payload)
				_, _ = conn.Write([]byte("tcp-pong"))
			case 53:
				payload := make([]byte, 8192)
				n, err := conn.Read(payload)
				if err != nil {
					requestLog <- "udp-read:" + err.Error()
					return
				}
				requestLog <- fmt.Sprintf("udp:%d", n)
				_, _ = conn.Write(payload[:n])
			}
		},
		ICMPEchoDelay: func() (time.Duration, bool) { return 0, true },
		LogPrefix:     "gre-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := targetStack.Start(); err != nil {
		t.Fatal(err)
	}

	clientEndpoint := channel.New(1024, config.mtu, "")
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
			datagram := testOuterGRE(config, inner, false, 0)
			decoded, err := decodeGREDatagram(datagram, config)
			if err != nil {
				continue
			}
			ingressPackets.Add(1)
			inbound := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), decoded.innerPacket...))})
			targetEndpoint.InjectInbound(decoded.networkProtocol, inbound)
			inbound.DecRef()
		}
	}()
	go func() {
		defer bridgeWG.Done()
		for {
			packet := targetEndpoint.ReadContext(bridgeCtx)
			if packet == nil {
				return
			}
			view := packet.ToView()
			packet.DecRef()
			fragments, err := fragmentIPPacket(view.AsSlice(), config.mtu)
			view.Release()
			if err != nil {
				continue
			}
			for _, fragment := range fragments {
				encoded, err := encodeGREPacket(fragment, config.mtu)
				if err != nil {
					continue
				}
				egressPackets.Add(1)
				inbound := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), encoded[4:]...))})
				clientEndpoint.InjectInbound(networkProtocolForPacket(fragment), inbound)
				inbound.DecRef()
			}
		}
	}()

	cleanup := func() {
		cancelBridge()
		bridgeWG.Wait()
		_ = targetStack.Close()
		clientStack.Close()
		for _, endpoint := range clientStack.CleanupEndpoints() {
			endpoint.Abort()
		}
		targetEndpoint.Close()
		clientEndpoint.Close()
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tcpConn, err := gonet.DialContextTCP(ctx, clientStack, tcpip.FullAddress{NIC: 1, Addr: targetAddress, Port: 443}, networkProtocol)
	if err != nil {
		t.Fatal(err)
	}
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
