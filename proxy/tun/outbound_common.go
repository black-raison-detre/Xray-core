package tun

import (
	"net/netip"
	"strings"
)

func needsOutboundInterface(address string) bool {
	addrPort, err := netip.ParseAddrPort(address)
	if err == nil && addrPort.Addr().IsLoopback() {
		return false
	}
	return !strings.HasPrefix(strings.ToLower(address), "localhost:")
}
