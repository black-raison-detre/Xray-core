package wireguard

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	featuresdns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport/internet"
)

type endpointLookupDNS struct {
	lookup func(string, featuresdns.IPOption) ([]xnet.IP, uint32, error)

	mu      sync.Mutex
	calls   int
	domain  string
	options featuresdns.IPOption
}

func (*endpointLookupDNS) Type() interface{} { return featuresdns.ClientType() }
func (*endpointLookupDNS) Start() error      { return nil }
func (*endpointLookupDNS) Close() error      { return nil }

func (d *endpointLookupDNS) LookupIP(domain string, options featuresdns.IPOption) ([]xnet.IP, uint32, error) {
	d.mu.Lock()
	d.calls++
	d.domain, d.options = domain, options
	d.mu.Unlock()
	return d.lookup(domain, options)
}

func (d *endpointLookupDNS) state() (int, string, featuresdns.IPOption) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls, d.domain, d.options
}

func TestLookupIPContextReturnsOnCancellation(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	d := &endpointLookupDNS{lookup: func(string, featuresdns.IPOption) ([]xnet.IP, uint32, error) {
		close(started)
		<-release
		return nil, 0, nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, _, err := lookupIPContext(ctx, d, "blocked.example")
		result <- err
	}()
	waitForLookup(t, started)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("lookupIPContext() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("lookupIPContext() did not return after cancellation")
	}
}

func TestLookupIPContextReturnsOnDeadline(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	d := &endpointLookupDNS{lookup: func(string, featuresdns.IPOption) ([]xnet.IP, uint32, error) {
		close(started)
		<-release
		return nil, 0, nil
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, _, err := lookupIPContext(ctx, d, "slow.example")
		result <- err
	}()
	waitForLookup(t, started)
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("lookupIPContext() error = %v, want context.DeadlineExceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("lookupIPContext() did not return after its deadline")
	}
}

func TestLookupIPContextSkipsLookupForCanceledContext(t *testing.T) {
	d := &endpointLookupDNS{lookup: func(string, featuresdns.IPOption) ([]xnet.IP, uint32, error) {
		return nil, 0, nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := lookupIPContext(ctx, d, "never.example")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("lookupIPContext() error = %v, want context.Canceled", err)
	}
	if calls, _, _ := d.state(); calls != 0 {
		t.Fatalf("DNS lookup calls = %d, want 0", calls)
	}
}

func TestLookupIPContextPreservesResultErrorTTLAndOptions(t *testing.T) {
	wantIP := xnet.ParseIP("198.51.100.24")
	wantErr := errors.New("lookup failed")
	for _, test := range []struct {
		name string
		ips  []xnet.IP
		ttl  uint32
		err  error
	}{
		{name: "result", ips: []xnet.IP{wantIP}, ttl: 73},
		{name: "error", ttl: 19, err: wantErr},
	} {
		t.Run(test.name, func(t *testing.T) {
			d := &endpointLookupDNS{lookup: func(string, featuresdns.IPOption) ([]xnet.IP, uint32, error) {
				return test.ips, test.ttl, test.err
			}}
			ips, ttl, err := lookupIPContext(context.Background(), d, "result.example")
			if !errors.Is(err, test.err) {
				t.Fatalf("lookupIPContext() error = %v, want %v", err, test.err)
			}
			if ttl != test.ttl {
				t.Fatalf("lookupIPContext() TTL = %d, want %d", ttl, test.ttl)
			}
			if len(ips) != len(test.ips) || (len(ips) != 0 && !ips[0].Equal(test.ips[0])) {
				t.Fatalf("lookupIPContext() IPs = %v, want %v", ips, test.ips)
			}
			calls, domain, options := d.state()
			if calls != 1 || domain != "result.example" || !options.IPv4Enable || !options.IPv6Enable {
				t.Fatalf("DNS call = (%d, %q, %+v), want one dual-stack lookup for result.example", calls, domain, options)
			}
		})
	}
}

func TestResolveLocalSelectsFamilyAndCachesByTTL(t *testing.T) {
	ips := []xnet.IP{xnet.ParseIP("2001:db8::24"), xnet.ParseIP("198.51.100.24")}
	for _, test := range []struct {
		strategy DeviceConfig_DomainStrategy
		wantIP   string
	}{
		{DeviceConfig_FORCE_IP4, "198.51.100.24"},
		{DeviceConfig_FORCE_IP6, "2001:db8::24"},
		{DeviceConfig_FORCE_IP46, "198.51.100.24"},
		{DeviceConfig_FORCE_IP64, "2001:db8::24"},
	} {
		t.Run(test.strategy.String(), func(t *testing.T) {
			d := &endpointLookupDNS{lookup: func(string, featuresdns.IPOption) ([]xnet.IP, uint32, error) {
				return ips, 60, nil
			}}
			h := &Handler{
				conf:  &DeviceConfig{DomainStrategy: test.strategy},
				dns:   d,
				cache: make(map[string]entry),
			}
			for i := 0; i < 2; i++ {
				ip, err := h.resolveLocal(context.Background(), "cached.example")
				if err != nil || ip.String() != test.wantIP {
					t.Fatalf("resolveLocal() = (%v, %v), want %s", ip, err, test.wantIP)
				}
			}
			if calls, _, _ := d.state(); calls != 1 {
				t.Fatalf("DNS lookup calls = %d, want 1 cached lookup", calls)
			}
		})
	}
}

func TestResolveLocalLiteralIPBypassesDNS(t *testing.T) {
	d := &endpointLookupDNS{lookup: func(string, featuresdns.IPOption) ([]xnet.IP, uint32, error) {
		return nil, 0, nil
	}}
	h := &Handler{conf: &DeviceConfig{DomainStrategy: DeviceConfig_FORCE_IP}, dns: d}
	want := xnet.ParseIP("203.0.113.9")
	got, err := h.resolveLocal(context.Background(), want.String())
	if err != nil || !got.Equal(want) {
		t.Fatalf("resolveLocal() = (%v, %v), want %v", got, err, want)
	}
	if calls, _, _ := d.state(); calls != 0 {
		t.Fatalf("DNS lookup calls = %d, want 0", calls)
	}
}

func TestHandlerInitCanceledEndpointLookupCanRetry(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	firstLookupDone := make(chan struct{})
	d := &endpointLookupDNS{}
	d.lookup = func(domain string, _ featuresdns.IPOption) ([]xnet.IP, uint32, error) {
		if domain != "peer.example" {
			return nil, 0, errors.New("unexpected DNS name: " + domain)
		}
		calls, _, _ := d.state()
		if calls == 1 {
			close(started)
			<-release
			close(firstLookupDone)
			return nil, 0, nil
		}
		return []xnet.IP{xnet.ParseIP("127.0.0.1")}, 60, nil
	}
	tun := newTestNetTun(t)
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
		streamSettings: &internet.MemoryStreamConfig{SocketSettings: &internet.SocketConfig{}},
		tun:            tun,
		cache:          make(map[string]entry),
	}
	t.Cleanup(func() { _ = h.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	initResult := make(chan error, 1)
	go func() { initResult <- h.init(ctx) }()
	waitForLookup(t, started)
	cancel()
	select {
	case err := <-initResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("first init() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("init() did not return after endpoint lookup cancellation")
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case <-firstLookupDone:
	case <-time.After(time.Second):
		t.Fatal("blocked DNS fixture did not finish after release")
	}
	if h.dev != nil || h.tun == nil {
		t.Fatalf("after canceled init, dev=%v tun=%v; want no device and a reusable TUN", h.dev, h.tun)
	}

	if err := h.init(context.Background()); err != nil {
		t.Fatalf("retry init() error = %v", err)
	}
	state, err := h.dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet() error = %v", err)
	}
	var endpoint string
	for _, line := range strings.Split(state, "\n") {
		if value, ok := strings.CutPrefix(line, "endpoint="); ok {
			endpoint = value
		}
	}
	addrPort, err := netip.ParseAddrPort(endpoint)
	if err != nil || addrPort.Addr().Unmap() != netip.MustParseAddr("127.0.0.1") || addrPort.Port() != 51820 {
		t.Fatalf("IpcGet() endpoint = %q, want loopback IPv4 port 51820 (parse error: %v)", endpoint, err)
	}
	if calls, _, _ := d.state(); calls != 2 {
		t.Fatalf("DNS lookup calls = %d, want one canceled lookup and one retry", calls)
	}
}

func waitForLookup(t *testing.T, started <-chan struct{}) {
	t.Helper()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("DNS lookup did not start")
	}
}
