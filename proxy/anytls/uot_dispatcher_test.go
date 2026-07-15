package anytls

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	udp_proto "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type uotTestDispatcher struct {
	mu           sync.Mutex
	destinations map[string]int
}

func (d *uotTestDispatcher) Dispatch(_ context.Context, destination net.Destination) (*transport.Link, error) {
	uplinkReader, uplinkWriter := pipe.New(pipe.WithSizeLimit(1024))
	downlinkReader, downlinkWriter := pipe.New(pipe.WithSizeLimit(1024))
	d.mu.Lock()
	d.destinations[destination.String()]++
	d.mu.Unlock()
	go func() {
		for {
			mb, err := uplinkReader.ReadMultiBuffer()
			if err != nil {
				return
			}
			if err := downlinkWriter.WriteMultiBuffer(mb); err != nil {
				return
			}
		}
	}()
	return &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}, nil
}

func (*uotTestDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	return nil
}
func (*uotTestDispatcher) Start() error      { return nil }
func (*uotTestDispatcher) Close() error      { return nil }
func (*uotTestDispatcher) Type() interface{} { return routing.DispatcherType() }

func TestUoTUnconnectedDispatchesEachDestinationSeparately(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := &uotTestDispatcher{destinations: make(map[string]int)}
	replies := make(chan net.Destination, 2)
	d := newUoTUnconnectedDispatcher(base, func(packet *udp_proto.Packet) {
		replies <- packet.Source
		packet.Payload.Release()
	})
	defer d.Close()

	first := net.UDPDestination(net.LocalHostIP, 10001)
	second := net.UDPDestination(net.LocalHostIP, 10002)
	d.Dispatch(ctx, first, buf.FromBytes([]byte("first")))
	d.Dispatch(ctx, second, buf.FromBytes([]byte("second")))

	seen := make(map[string]bool)
	for range 2 {
		select {
		case destination := <-replies:
			seen[destination.String()] = true
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for UoT response")
		}
	}
	if !seen[first.String()] || !seen[second.String()] {
		t.Fatalf("response destinations = %#v", seen)
	}
	base.mu.Lock()
	defer base.mu.Unlock()
	if base.destinations[first.String()] != 1 || base.destinations[second.String()] != 1 {
		t.Fatalf("dispatches = %#v", base.destinations)
	}
}
