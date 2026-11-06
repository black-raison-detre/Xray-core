package wireguard

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	featuresdns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

func TestHandlerInitUsesNumericEndpointForDefaultSocket(t *testing.T) {
	d := &endpointLookupDNS{lookup: func(string, featuresdns.IPOption) ([]xnet.IP, uint32, error) {
		return []xnet.IP{xnet.ParseIP("198.51.100.41")}, 60, nil
	}}
	dialer := &endpointPolicySystemDialer{destinations: make(chan xnet.Destination, 1)}
	installEndpointPolicyDialer(t, d, dialer, nil)
	h := newEndpointPolicyHandler(t, d, nil)
	if err := h.init(context.Background()); err != nil {
		t.Fatalf("init() error = %v", err)
	}
	dest := waitEndpointPolicyDestination(t, dialer.destinations)
	if dest.Address.Family().IsDomain() || dest.Address.String() != "198.51.100.41" {
		t.Fatalf("default socket destination = %s, want resolved IPv4 literal", dest)
	}
	if dest.Port.Value() != 51820 {
		t.Fatalf("default socket port = %d, want 51820", dest.Port.Value())
	}
}

func TestHandlerInitPreservesExplicitSocketResolutionPolicies(t *testing.T) {
	for _, test := range []struct {
		name   string
		socket *internet.SocketConfig
		want   string
		calls  int
	}{
		{
			name:   "domain strategy resolves at socket dial",
			socket: &internet.SocketConfig{DomainStrategy: internet.DomainStrategy_FORCE_IP4},
			want:   "198.51.100.42",
			calls:  2,
		},
		{
			name:   "address port strategy receives hostname",
			socket: &internet.SocketConfig{AddressPortStrategy: internet.AddressPortStrategy_SrvPortOnly},
			want:   "peer.example",
			calls:  1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			d := &endpointLookupDNS{}
			d.lookup = func(string, featuresdns.IPOption) ([]xnet.IP, uint32, error) {
				calls, _, _ := d.state()
				ip := "198.51.100.41"
				if calls > 1 {
					ip = "198.51.100.42"
				}
				return []xnet.IP{xnet.ParseIP(ip)}, 60, nil
			}
			dialer := &endpointPolicySystemDialer{destinations: make(chan xnet.Destination, 1)}
			installEndpointPolicyDialer(t, d, dialer, nil)
			h := newEndpointPolicyHandler(t, d, test.socket)
			if err := h.init(context.Background()); err != nil {
				t.Fatalf("init() error = %v", err)
			}
			dest := waitEndpointPolicyDestination(t, dialer.destinations)
			if got := dest.Address.String(); got != test.want {
				t.Fatalf("socket destination = %s, want %s", got, test.want)
			}
			if calls, _, _ := d.state(); calls != test.calls {
				t.Fatalf("DNS lookup calls = %d, want %d", calls, test.calls)
			}
		})
	}
}

func TestHandlerInitPreservesHostnameForDialerProxy(t *testing.T) {
	d := &endpointLookupDNS{lookup: func(string, featuresdns.IPOption) ([]xnet.IP, uint32, error) {
		return []xnet.IP{xnet.ParseIP("198.51.100.41")}, 60, nil
	}}
	handler := &endpointPolicyOutboundHandler{destinations: make(chan xnet.Destination, 1)}
	manager := &endpointPolicyOutboundManager{handler: handler}
	installEndpointPolicyDialer(t, d, nil, manager)
	h := newEndpointPolicyHandler(t, d, &internet.SocketConfig{DialerProxy: "chain"})
	if err := h.init(context.Background()); err != nil {
		t.Fatalf("init() error = %v", err)
	}
	select {
	case dest := <-handler.destinations:
		if !dest.Address.Family().IsDomain() || dest.Address.String() != "peer.example" {
			t.Fatalf("chained outbound target = %s, want peer.example hostname", dest)
		}
		if dest.Port.Value() != 51820 {
			t.Fatalf("chained outbound port = %d, want 51820", dest.Port.Value())
		}
	case <-time.After(time.Second):
		t.Fatal("chained outbound handler did not receive the endpoint target")
	}
}

func installEndpointPolicyDialer(t *testing.T, d featuresdns.Client, dialer internet.SystemDialer, manager outbound.Manager) {
	t.Helper()
	internet.InitSystemDialer(d, manager)
	internet.UseAlternativeSystemDialer(dialer)
	t.Cleanup(func() {
		internet.UseAlternativeSystemDialer(nil)
		internet.InitSystemDialer(nil, nil)
	})
}

func newEndpointPolicyHandler(t *testing.T, d *endpointLookupDNS, socket *internet.SocketConfig) *Handler {
	t.Helper()
	h := &Handler{
		conf: &DeviceConfig{
			SecretKey:      strings.Repeat("01", 32),
			DomainStrategy: DeviceConfig_FORCE_IP4,
			Peers: []*PeerConfig{{
				PublicKey:  strings.Repeat("02", 32),
				Endpoint:   "peer.example:51820",
				AllowedIps: []string{"0.0.0.0/0"},
			}},
		},
		dns:            d,
		streamSettings: &internet.MemoryStreamConfig{SocketSettings: socket},
		tun:            newTestNetTun(t),
		cache:          make(map[string]entry),
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}

type endpointPolicySystemDialer struct {
	destinations chan xnet.Destination
}

func (d *endpointPolicySystemDialer) Dial(_ context.Context, _ xnet.Address, dest xnet.Destination, _ *internet.SocketConfig) (net.Conn, error) {
	d.destinations <- dest
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return &internet.PacketConnWrapper{PacketConn: pc, Dest: pc.LocalAddr()}, nil
}

func (*endpointPolicySystemDialer) DestIpAddress() xnet.IP { return nil }

func waitEndpointPolicyDestination(t *testing.T, destinations <-chan xnet.Destination) xnet.Destination {
	t.Helper()
	select {
	case dest := <-destinations:
		return dest
	case <-time.After(time.Second):
		t.Fatal("system dialer did not receive a destination")
		return xnet.Destination{}
	}
}

type endpointPolicyOutboundHandler struct {
	destinations chan xnet.Destination
}

func (*endpointPolicyOutboundHandler) Start() error                         { return nil }
func (*endpointPolicyOutboundHandler) Close() error                         { return nil }
func (*endpointPolicyOutboundHandler) Tag() string                          { return "chain" }
func (*endpointPolicyOutboundHandler) SenderSettings() *serial.TypedMessage { return nil }
func (*endpointPolicyOutboundHandler) ProxySettings() *serial.TypedMessage  { return nil }
func (h *endpointPolicyOutboundHandler) Dispatch(ctx context.Context, _ *transport.Link) {
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) > 0 {
		h.destinations <- outbounds[len(outbounds)-1].Target
	}
}

type endpointPolicyOutboundManager struct {
	handler outbound.Handler
}

func (*endpointPolicyOutboundManager) Type() interface{} { return outbound.ManagerType() }
func (*endpointPolicyOutboundManager) Start() error      { return nil }
func (*endpointPolicyOutboundManager) Close() error      { return nil }
func (m *endpointPolicyOutboundManager) GetHandler(string) outbound.Handler {
	return m.handler
}
func (m *endpointPolicyOutboundManager) GetDefaultHandler() outbound.Handler { return m.handler }
func (*endpointPolicyOutboundManager) AddHandler(context.Context, outbound.Handler) error {
	return nil
}
func (*endpointPolicyOutboundManager) RemoveHandler(context.Context, string) error { return nil }
func (m *endpointPolicyOutboundManager) ListHandlers(context.Context) []outbound.Handler {
	return []outbound.Handler{m.handler}
}
