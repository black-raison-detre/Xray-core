package tun

import "testing"

func TestLoopbackOutboundDoesNotRequireSelectedInterface(t *testing.T) {
	for _, address := range []string{"127.0.0.1:53", "[::1]:1080", "localhost:8080", "LOCALHOST:443"} {
		if needsOutboundInterface(address) {
			t.Errorf("%q incorrectly requires a selected adapter", address)
		}
	}
	for _, address := range []string{"192.0.2.10:53", "[2001:db8::1]:443", "example.com:443"} {
		if !needsOutboundInterface(address) {
			t.Errorf("%q incorrectly bypasses adapter selection", address)
		}
	}
}
