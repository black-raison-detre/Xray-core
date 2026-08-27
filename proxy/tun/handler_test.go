package tun

import (
	"bytes"
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/extension"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"google.golang.org/protobuf/proto"
)

type testCounter struct {
	value int64
}

func (c *testCounter) Value() int64 {
	return atomic.LoadInt64(&c.value)
}

func (c *testCounter) Set(value int64) int64 {
	return atomic.SwapInt64(&c.value, value)
}

func (c *testCounter) Add(value int64) int64 {
	return atomic.AddInt64(&c.value, value) - value
}

type testConn struct {
	reader *bytes.Reader
	writer bytes.Buffer
}

func newTestConn(input []byte) *testConn {
	return &testConn{reader: bytes.NewReader(input)}
}

func (c *testConn) Read(payload []byte) (int, error) {
	return c.reader.Read(payload)
}

func (c *testConn) Write(payload []byte) (int, error) {
	return c.writer.Write(payload)
}

func (c *testConn) Close() error {
	return nil
}

func (c *testConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1080}
}

func (c *testConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 12345}
}

func (c *testConn) SetDeadline(time.Time) error {
	return nil
}

func (c *testConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *testConn) SetWriteDeadline(time.Time) error {
	return nil
}

type testDispatcher struct {
	writePayload []byte
	readBytes    int32
}

type testObservatory struct {
	report proto.Message
	err    error
}

func (o *testObservatory) Type() interface{} {
	return extension.ObservatoryType()
}

func (o *testObservatory) Start() error {
	return nil
}

func (o *testObservatory) Close() error {
	return nil
}

func (o *testObservatory) GetObservation(context.Context) (proto.Message, error) {
	return o.report, o.err
}

func (d *testDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

func (d *testDispatcher) Start() error {
	return nil
}

func (d *testDispatcher) Close() error {
	return nil
}

func (d *testDispatcher) Dispatch(context.Context, xnet.Destination) (*transport.Link, error) {
	return nil, nil
}

func (d *testDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	mb, err := link.Reader.ReadMultiBuffer()
	if err != nil {
		return err
	}
	atomic.StoreInt32(&d.readBytes, mb.Len())
	buf.ReleaseMulti(mb)

	return link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(d.writePayload)})
}

func TestHandlerCountsTunConnectionTraffic(t *testing.T) {
	uplinkCounter := new(testCounter)
	downlinkCounter := new(testCounter)
	dispatcher := &testDispatcher{writePayload: []byte("downlink")}
	conn := newTestConn([]byte("uplink"))

	handler := &Handler{
		ctx:             context.Background(),
		config:          &Config{},
		dispatcher:      dispatcher,
		uplinkCounter:   uplinkCounter,
		downlinkCounter: downlinkCounter,
	}
	handler.HandleConnection(conn, xnet.TCPDestination(xnet.LocalHostIP, 443))

	if got := uplinkCounter.Value(); got != int64(len("uplink")) {
		t.Fatalf("unexpected uplink counter: got %d, want %d", got, len("uplink"))
	}
	if got := downlinkCounter.Value(); got != int64(len("downlink")) {
		t.Fatalf("unexpected downlink counter: got %d, want %d", got, len("downlink"))
	}
	if got := int(atomic.LoadInt32(&dispatcher.readBytes)); got != len("uplink") {
		t.Fatalf("dispatcher read unexpected bytes: got %d, want %d", got, len("uplink"))
	}
	if got := conn.writer.String(); got != "downlink" {
		t.Fatalf("connection write mismatch: got %q, want %q", got, "downlink")
	}
}

func TestHandlerICMPEchoDelay(t *testing.T) {
	tests := []struct {
		name        string
		mode        IcmpMode
		observatory extension.Observatory
		wantDelay   time.Duration
		wantOK      bool
	}{
		{
			name:   "fake is immediate without observatory",
			mode:   IcmpMode_FAKE,
			wantOK: true,
		},
		{
			name: "probe requires observatory",
			mode: IcmpMode_PROBE,
		},
		{
			name: "probe selects lowest alive cached delay",
			mode: IcmpMode_PROBE,
			observatory: &testObservatory{report: &observatory.ObservationResult{Status: []*observatory.OutboundStatus{
				{OutboundTag: "dead", Alive: false, Delay: 1},
				{OutboundTag: "slow", Alive: true, Delay: 85},
				{OutboundTag: "fast", Alive: true, Delay: 42},
			}}},
			wantDelay: 42 * time.Millisecond,
			wantOK:    true,
		},
		{
			name: "probe drops when no alive result exists",
			mode: IcmpMode_PROBE,
			observatory: &testObservatory{report: &observatory.ObservationResult{Status: []*observatory.OutboundStatus{
				{OutboundTag: "dead", Alive: false, Delay: 99999999},
			}}},
		},
		{
			name: "probe drops excessive cached delay",
			mode: IcmpMode_PROBE,
			observatory: &testObservatory{report: &observatory.ObservationResult{Status: []*observatory.OutboundStatus{
				{OutboundTag: "too-slow", Alive: true, Delay: maxICMPProbeDelay.Milliseconds() + 1},
			}}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := &Handler{
				ctx:         context.Background(),
				config:      &Config{IcmpMode: test.mode},
				observatory: test.observatory,
			}
			gotDelay, gotOK := handler.icmpEchoDelay()
			if gotDelay != test.wantDelay || gotOK != test.wantOK {
				t.Fatalf("icmpEchoDelay() = (%s, %v), want (%s, %v)", gotDelay, gotOK, test.wantDelay, test.wantOK)
			}
		})
	}
}

func TestHandlerICMPModeObservatoryDependency(t *testing.T) {
	tests := []struct {
		name            string
		mode            IcmpMode
		withObservatory bool
		wantError       bool
	}{
		{
			name: "fake without observatory",
			mode: IcmpMode_FAKE,
		},
		{
			name:      "probe without observatory",
			mode:      IcmpMode_PROBE,
			wantError: true,
		},
		{
			name:            "probe with observatory",
			mode:            IcmpMode_PROBE,
			withObservatory: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			instance, err := core.New(&core.Config{})
			if err != nil {
				t.Fatal(err)
			}
			defer instance.Close()

			if err := instance.AddFeature(&testDispatcher{}); err != nil {
				t.Fatal(err)
			}
			var expectedObservatory extension.Observatory
			if test.withObservatory {
				expectedObservatory = &testObservatory{report: &observatory.ObservationResult{}}
				if err := instance.AddFeature(expectedObservatory); err != nil {
					t.Fatal(err)
				}
			}

			rawHandler, err := core.CreateObject(instance, &Config{IcmpMode: test.mode})
			if test.wantError {
				if err == nil || !strings.Contains(err.Error(), "requires Observatory") {
					t.Fatalf("CreateObject() error = %v, want missing Observatory error", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			handler, ok := rawHandler.(*Handler)
			if !ok {
				t.Fatalf("CreateObject() returned %T, want *Handler", rawHandler)
			}
			defer handler.Close()
			if handler.observatory != expectedObservatory {
				t.Fatalf("Handler observatory = %T, want %T", handler.observatory, expectedObservatory)
			}
		})
	}
}
