//go:build routeros_gre

package conf

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xtls/xray-core/proxy/gre"
)

func TestGREConfigBuild(t *testing.T) {
	message, err := (&GREConfig{
		LocalAddress: "172.31.255.2", RemoteAddress: "172.31.255.1",
		AllowedInnerSources: []string{"192.168.50.100/32"}, ICMPMode: " PrObE ",
	}).Build()
	if err != nil {
		t.Fatal(err)
	}
	config := message.(*gre.Config)
	if config.GetMtu() != 1400 || config.GetIcmpMode() != gre.IcmpMode_PROBE {
		t.Fatalf("unexpected GRE defaults: %#v", config)
	}
}

func TestGREConfigValidation(t *testing.T) {
	tests := []struct {
		name   string
		config GREConfig
		want   string
	}{
		{name: "missing peer", config: GREConfig{LocalAddress: "172.31.255.2", AllowedInnerSources: []string{"192.168.50.100/32"}}, want: "remoteAddress"},
		{name: "same peer", config: GREConfig{LocalAddress: "172.31.255.2", RemoteAddress: "172.31.255.2", AllowedInnerSources: []string{"192.168.50.100/32"}}, want: "must differ"},
		{name: "empty sources", config: GREConfig{LocalAddress: "172.31.255.2", RemoteAddress: "172.31.255.1"}, want: "must not be empty"},
		{name: "ipv6 source", config: GREConfig{LocalAddress: "172.31.255.2", RemoteAddress: "172.31.255.1", AllowedInnerSources: []string{"2001:db8::/64"}}, want: "IPv4 CIDRs"},
		{name: "large mtu", config: GREConfig{LocalAddress: "172.31.255.2", RemoteAddress: "172.31.255.1", AllowedInnerSources: []string{"192.168.50.100/32"}, MTU: 1473}, want: "576..1472"},
		{name: "unknown icmp", config: GREConfig{LocalAddress: "172.31.255.2", RemoteAddress: "172.31.255.1", AllowedInnerSources: []string{"192.168.50.100/32"}, ICMPMode: "remote"}, want: "unknown GRE ICMP"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.config.Build(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Build error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestGREInboundRejectsListenerFields(t *testing.T) {
	config := &InboundDetourConfig{Protocol: "gre", PortList: &PortList{Range: []PortRange{{From: 47, To: 47}}}}
	if _, err := config.Build(); err == nil || !strings.Contains(err.Error(), "does not accept") {
		t.Fatalf("Build error = %v, want pseudo-inbound field rejection", err)
	}
}

func TestGREInboundBuildsWithoutListener(t *testing.T) {
	settings := json.RawMessage(`{
		"localAddress":"172.31.255.2",
		"remoteAddress":"172.31.255.1",
		"allowedInnerSources":["192.168.50.100/32"]
	}`)
	built, err := (&InboundDetourConfig{Protocol: "gre", Tag: "gre-routeros", Settings: &settings}).Build()
	if err != nil {
		t.Fatal(err)
	}
	if got := built.GetProxySettings().GetType(); got != "xray.proxy.gre.Config" {
		t.Fatalf("proxy settings type = %q", got)
	}
}
