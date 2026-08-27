//go:build routeros_gre && linux

package gre

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestRawDeviceCloseUnblocksWorkers(t *testing.T) {
	device, err := newPacketDevice(context.Background(), runtimeConfig{
		local: netip.MustParseAddr("127.0.0.1"), remote: netip.MustParseAddr("127.0.0.2"),
		allowed: []netip.Prefix{netip.MustParsePrefix("192.168.50.100/32")}, mtu: 1400,
	})
	if err != nil {
		if strings.Contains(err.Error(), "CAP_NET_RAW") {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	if err := device.Start(); err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- device.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("raw GRE device close did not unblock workers")
	}
	if err := device.Close(); err != nil {
		t.Fatalf("second close failed: %v", err)
	}
}
