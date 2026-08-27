//go:build routeros_gre

package gre

import (
	"context"
	"io"
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
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func TestGREInMemoryTCPAndUDPFlow(t *testing.T) {
	config := testRuntimeConfig(t)
	targetAddress := tcpip.AddrFrom4([4]byte{198, 51, 100, 10})
	clientAddress := tcpip.AddrFrom4(config.allowed[0].Addr().As4())
	targetEndpoint := channel.New(1024, config.mtu, "")

	requestLog := make(chan string, 2)
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
				payload := make([]byte, 64)
				n, err := conn.Read(payload)
				if err != nil {
					requestLog <- "udp-read:" + err.Error()
					return
				}
				requestLog <- string(payload[:n])
				_, _ = conn.Write([]byte("udp-pong"))
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
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if err := clientStack.CreateNIC(1, clientEndpoint); err != nil {
		t.Fatal(err.String())
	}
	if err := clientStack.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: clientAddress.WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		t.Fatal(err.String())
	}
	clientStack.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})

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
			inbound := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), decoded.innerIPv4...))})
			targetEndpoint.InjectInbound(header.IPv4ProtocolNumber, inbound)
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
			encoded, err := encodeGREPacket(view.AsSlice(), config.mtu)
			view.Release()
			if err != nil {
				continue
			}
			egressPackets.Add(1)
			inbound := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), encoded[4:]...))})
			clientEndpoint.InjectInbound(header.IPv4ProtocolNumber, inbound)
			inbound.DecRef()
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
	tcpConn, err := gonet.DialContextTCP(ctx, clientStack, tcpip.FullAddress{NIC: 1, Addr: targetAddress, Port: 443}, ipv4.ProtocolNumber)
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

	udpConn, err := gonet.DialUDP(
		clientStack,
		&tcpip.FullAddress{NIC: 1, Addr: clientAddress, Port: 53000},
		&tcpip.FullAddress{NIC: 1, Addr: targetAddress, Port: 53},
		ipv4.ProtocolNumber,
	)
	if err != nil {
		t.Fatal(err)
	}
	_ = udpConn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := udpConn.Write([]byte("udp-ping")); err != nil {
		t.Fatal(err)
	}
	udpReply := make([]byte, len("udp-pong"))
	if _, err := io.ReadFull(udpConn, udpReply); err != nil {
		t.Fatal(err)
	}
	_ = udpConn.Close()
	if string(udpReply) != "udp-pong" {
		t.Fatalf("UDP reply = %q", udpReply)
	}

	seen := map[string]bool{}
	for range 2 {
		select {
		case request := <-requestLog:
			seen[request] = true
		case <-ctx.Done():
			t.Fatal("timed out waiting for dispatcher-side requests")
		}
	}
	if !seen["tcp-ping"] || !seen["udp-ping"] {
		t.Fatalf("dispatcher-side requests = %#v", seen)
	}
	if ingressPackets.Load() == 0 || egressPackets.Load() == 0 {
		t.Fatalf("GRE packet counters ingress=%d egress=%d", ingressPackets.Load(), egressPackets.Load())
	}
}
