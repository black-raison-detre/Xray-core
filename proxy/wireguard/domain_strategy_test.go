package wireguard

import (
	"context"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport/internet"
)

func TestSelectWireGuardDomainAddresses(t *testing.T) {
	input := []netip.AddrPort{
		netip.MustParseAddrPort("[2001:db8::1]:443"),
		netip.MustParseAddrPort("192.0.2.1:443"),
		netip.MustParseAddrPort("192.0.2.2:443"),
		netip.MustParseAddrPort("[2001:db8::2]:443"),
	}
	tests := []struct {
		name     string
		strategy *DeviceConfig_DomainStrategy
		input    []netip.AddrPort
		want     []netip.AddrPort
	}{
		{name: "unset preserves upstream order", input: input, want: input},
		{name: "force ip keeps both families", strategy: wgDomainStrategy(DeviceConfig_FORCE_IP), input: input, want: input},
		{
			name:     "force ipv4 filters and preserves order",
			strategy: wgDomainStrategy(DeviceConfig_FORCE_IP4),
			input:    input,
			want:     input[1:3],
		},
		{
			name:     "force ipv6 filters and preserves order",
			strategy: wgDomainStrategy(DeviceConfig_FORCE_IP6),
			input:    input,
			want:     []netip.AddrPort{input[0], input[3]},
		},
		{
			name:     "force ipv4 then ipv6 prefers ipv4",
			strategy: wgDomainStrategy(DeviceConfig_FORCE_IP46),
			input:    input,
			want:     input[1:3],
		},
		{
			name:     "force ipv4 then ipv6 falls back",
			strategy: wgDomainStrategy(DeviceConfig_FORCE_IP46),
			input:    []netip.AddrPort{input[0], input[3]},
			want:     []netip.AddrPort{input[0], input[3]},
		},
		{
			name:     "force ipv6 then ipv4 prefers ipv6",
			strategy: wgDomainStrategy(DeviceConfig_FORCE_IP64),
			input:    input,
			want:     []netip.AddrPort{input[0], input[3]},
		},
		{
			name:     "force ipv6 then ipv4 falls back",
			strategy: wgDomainStrategy(DeviceConfig_FORCE_IP64),
			input:    input[1:3],
			want:     input[1:3],
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := selectWireGuardDomainAddresses(test.input, test.strategy)
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("selected addresses = %v, want %v", got, test.want)
			}
		})
	}
}

func TestNetDialContextAppliesStrategyAfterFamilyEligibility(t *testing.T) {
	ipv4 := netip.MustParseAddrPort("192.0.2.1:443")
	ipv6 := netip.MustParseAddrPort("[2001:db8::1]:443")
	tests := []struct {
		name     string
		network  string
		strategy *DeviceConfig_DomainStrategy
		hasV4    bool
		hasV6    bool
		answers  []string
		want     []netip.AddrPort
	}{
		{
			name:     "tcp4 falls back from preferred ipv6",
			network:  "tcp4",
			strategy: wgDomainStrategy(DeviceConfig_FORCE_IP64),
			hasV4:    true,
			hasV6:    true,
			answers:  []string{ipv6.Addr().String(), ipv4.Addr().String()},
			want:     []netip.AddrPort{ipv4},
		},
		{
			name:     "tcp6 falls back from preferred ipv4",
			network:  "tcp6",
			strategy: wgDomainStrategy(DeviceConfig_FORCE_IP46),
			hasV4:    true,
			hasV6:    true,
			answers:  []string{ipv4.Addr().String(), ipv6.Addr().String()},
			want:     []netip.AddrPort{ipv6},
		},
		{
			name:     "ipv4-only tunnel falls back to ipv4",
			network:  "tcp",
			strategy: wgDomainStrategy(DeviceConfig_FORCE_IP64),
			hasV4:    true,
			answers:  []string{ipv4.Addr().String()},
			want:     []netip.AddrPort{ipv4},
		},
		{
			name:     "ipv6-only tunnel falls back to ipv6",
			network:  "tcp",
			strategy: wgDomainStrategy(DeviceConfig_FORCE_IP46),
			hasV6:    true,
			answers:  []string{ipv6.Addr().String()},
			want:     []netip.AddrPort{ipv6},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var attempted []netip.AddrPort
			tnet := &Net{
				hasV4:          test.hasV4,
				hasV6:          test.hasV6,
				domainStrategy: test.strategy,
				DialContextTCPAddrPort: func(_ context.Context, addr netip.AddrPort) (net.Conn, error) {
					attempted = append(attempted, addr)
					return nil, nil
				},
			}
			tnet.cache = cache{
				running: true,
				m: map[string]entry{
					"wg.example": {saddr: test.answers, deadline: time.Now().Add(time.Minute)},
				},
			}

			if _, err := tnet.DialContext(context.Background(), test.network, "wg.example:443"); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(attempted, test.want) {
				t.Fatalf("dial attempts = %v, want %v", attempted, test.want)
			}
		})
	}
}

func TestMakeResolveLocalDomainStrategyCompatibility(t *testing.T) {
	ipv4 := net.ParseIP("192.0.2.10")
	ipv6 := net.ParseIP("2001:db8::10")
	dnsClient := fixedWireGuardDNS{ips: []xnet.IP{ipv4, ipv6}}
	tests := []struct {
		name       string
		stream     *internet.MemoryStreamConfig
		compat     *DeviceConfig_DomainStrategy
		ips        []xnet.IP
		want       string
		wantEither []string
		wantErr    bool
	}{
		{
			name:   "unset retains upstream socket strategy",
			stream: &internet.MemoryStreamConfig{SocketSettings: &internet.SocketConfig{DomainStrategy: internet.DomainStrategy_FORCE_IP6}},
			ips:    dnsClient.ips,
			want:   ipv6.String(),
		},
		{
			name:   "compat strategy overrides resolver family",
			stream: &internet.MemoryStreamConfig{SocketSettings: &internet.SocketConfig{DomainStrategy: internet.DomainStrategy_FORCE_IP6}},
			compat: wgDomainStrategy(DeviceConfig_FORCE_IP4),
			ips:    dnsClient.ips,
			want:   ipv4.String(),
		},
		{
			name:   "compat preference falls back when family is absent",
			stream: &internet.MemoryStreamConfig{},
			compat: wgDomainStrategy(DeviceConfig_FORCE_IP46),
			ips:    []xnet.IP{ipv6},
			want:   ipv6.String(),
		},
		{
			name:    "compat single-family strategy rejects missing family",
			stream:  &internet.MemoryStreamConfig{},
			compat:  wgDomainStrategy(DeviceConfig_FORCE_IP4),
			ips:     []xnet.IP{ipv6},
			wantErr: true,
		},
		{
			name:       "unset socket settings retain all upstream answers",
			stream:     &internet.MemoryStreamConfig{},
			ips:        dnsClient.ips,
			wantEither: []string{ipv4.String(), ipv6.String()},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := makeResolveLocal(fixedWireGuardDNS{ips: test.ips}, test.stream, test.compat)
			got, err := resolver("peer.example")
			if test.wantErr {
				if err == nil {
					t.Fatal("resolver succeeded without an address in the required family")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if test.want != "" {
				if got.String() != test.want {
					t.Fatalf("resolved IP = %s, want %s", got, test.want)
				}
				return
			}
			for _, want := range test.wantEither {
				if got.String() == want {
					return
				}
			}
			t.Fatalf("resolved IP = %s, want one of %v", got, test.wantEither)
		})
	}
}

type fixedWireGuardDNS struct {
	dns.Client
	ips []xnet.IP
}

func (d fixedWireGuardDNS) LookupIP(string, dns.IPOption) ([]xnet.IP, uint32, error) {
	return d.ips, 60, nil
}

func wgDomainStrategy(strategy DeviceConfig_DomainStrategy) *DeviceConfig_DomainStrategy {
	return &strategy
}
