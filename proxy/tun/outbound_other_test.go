//go:build !windows

package tun

import (
	"net"
	"testing"
)

func TestClosedInterfaceUpdaterDoesNotExposeStaleSelection(t *testing.T) {
	updater := &InterfaceUpdater{}
	updater.iface = &net.Interface{Name: "old adapter", Index: 1}
	updater.Close()
	if !updater.Closed() || updater.Get() != nil {
		t.Fatalf("closed updater retained its selection: closed=%t iface=%v", updater.Closed(), updater.Get())
	}
	updater.Update()
	if updater.Get() != nil {
		t.Fatalf("closed updater accepted a late refresh: %v", updater.Get())
	}
}
