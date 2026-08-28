//go:build !routeros_gre

package conf

import (
	"testing"

	"github.com/xtls/xray-core/proxy/tun"
)

func TestTunICMPMode(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  tun.IcmpMode
	}{
		{name: "default", want: tun.IcmpMode_FAKE},
		{name: "fake", value: " fake ", want: tun.IcmpMode_FAKE},
		{name: "probe", value: "PrObE", want: tun.IcmpMode_PROBE},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message, err := (&TunConfig{ICMPMode: test.value}).Build()
			if err != nil {
				t.Fatal(err)
			}
			config := message.(*tun.Config)
			if config.IcmpMode != test.want {
				t.Fatalf("IcmpMode = %v, want %v", config.IcmpMode, test.want)
			}
		})
	}
}

func TestTunDescription(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "default", want: "Wintun"},
		{name: "custom", value: "Xray-GUI TUN", want: "Xray-GUI TUN"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message, err := (&TunConfig{Desc: test.value}).Build()
			if err != nil {
				t.Fatal(err)
			}
			config := message.(*tun.Config)
			if config.Desc != test.want {
				t.Fatalf("Desc = %q, want %q", config.Desc, test.want)
			}
		})
	}
}

func TestTunRejectsUnknownICMPMode(t *testing.T) {
	if _, err := (&TunConfig{ICMPMode: "remote"}).Build(); err == nil {
		t.Fatal("expected unknown icmpMode to fail")
	}
}

func TestTunConfigRegistered(t *testing.T) {
	if _, err := inboundConfigLoader.LoadWithID([]byte(`{}`), "tun"); err != nil {
		t.Fatal(err)
	}
	if !noListenerInboundProtocols["tun"] {
		t.Fatal("tun is not registered as a no-listener inbound")
	}
}
