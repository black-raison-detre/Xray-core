//go:build routeros_gre

package conf

import (
	"strings"
	"testing"
)

func TestRouterOSBuildExcludesTUNConfig(t *testing.T) {
	if _, err := inboundConfigLoader.LoadWithID([]byte(`{}`), "tun"); err == nil || !strings.Contains(err.Error(), "unknown config id") {
		t.Fatalf("TUN loader error = %v, want RouterOS build-tag gate", err)
	}
	if noListenerInboundProtocols["tun"] {
		t.Fatal("TUN remains registered as a RouterOS pseudo-inbound")
	}
}
