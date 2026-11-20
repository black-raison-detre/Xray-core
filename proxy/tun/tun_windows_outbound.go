//go:build windows

package tun

import (
	"context"
	"slices"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/features/egress"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// outboundGuard keeps Windows from sending sockets bound to an egress adapter
// back into the app-owned TUN through weak-host forwarding. It restores every
// family setting it changes when selection moves or the TUN closes.
type outboundGuard struct {
	sync.Mutex
	families   []winipcfg.AddressFamily
	manager    *egress.Manager
	turnedOff  map[winipcfg.AddressFamily]guardBinding
	forwarding string
	stopped    bool
}

type guardBinding struct {
	luid winipcfg.LUID
	name string
}

func (g *outboundGuard) check() {
	g.Lock()
	defer g.Unlock()
	if g.stopped {
		return
	}
	wanted := make(map[winipcfg.AddressFamily]guardBinding, len(g.families))
	if g.manager != nil {
		snapshot := g.manager.Snapshot()
		if snapshot.State == "active" {
			for _, family := range g.families {
				status := snapshot.IPv4
				index := uint32(0)
				if family == windows.AF_INET6 {
					status = snapshot.IPv6
				}
				if status.State != "selected" || status.Interface == nil {
					continue
				}
				if family == windows.AF_INET {
					index = status.Interface.Index
				} else {
					index = status.Interface.IPv6Index
				}
				if index == 0 {
					continue
				}
				if luid, err := winipcfg.LUIDFromIndex(index); err == nil {
					wanted[family] = guardBinding{luid: luid, name: status.Interface.Name}
				}
			}
		}
	} else if updater != nil {
		if iface := updater.Get(); iface != nil {
			if luid, err := winipcfg.LUIDFromIndex(uint32(iface.Index)); err == nil {
				for _, family := range g.families {
					wanted[family] = guardBinding{luid: luid, name: iface.Name}
				}
			}
		}
	}
	if g.turnedOff == nil {
		g.turnedOff = make(map[winipcfg.AddressFamily]guardBinding)
	}
	for family, previous := range g.turnedOff {
		current, ok := wanted[family]
		if ok && current.luid == previous.luid {
			continue
		}
		g.restoreBindingLocked(family, previous)
		delete(g.turnedOff, family)
	}

	var forwarding []string
	for family, binding := range wanted {
		row, err := binding.luid.IPInterface(family)
		if err != nil {
			continue
		}
		if row.ForwardingEnabled {
			forwarding = append(forwarding, familyName(family)+" on "+binding.name)
		}
		if !row.WeakHostSend {
			continue
		}
		if err := setWeakHostSend(row, false); err != nil {
			errors.LogWarningInner(context.Background(), err, "[tun] unable to turn weak host send off for ", familyName(family), " on ", binding.name)
			continue
		}
		g.turnedOff[family] = binding
		errors.LogInfo(context.Background(), "[tun] weak host send turned off for ", familyName(family), " on ", binding.name, " while the TUN runs, as Windows would ignore autoOutboundsInterface")
	}

	slices.Sort(forwarding)
	forwardingState := strings.Join(forwarding, ", ")
	if forwardingState != "" && forwardingState != g.forwarding {
		errors.LogWarning(context.Background(), "[tun] forwarding is on for ", forwardingState, " (Mobile Hotspot and Internet Connection Sharing turn it on), so Windows may ignore autoOutboundsInterface and send Xray's own connections into the TUN")
	}
	g.forwarding = forwardingState
}

func (g *outboundGuard) restore() {
	g.Lock()
	defer g.Unlock()
	g.restoreLocked()
	g.stopped = true
}

func (g *outboundGuard) restoreLocked() {
	for family, binding := range g.turnedOff {
		g.restoreBindingLocked(family, binding)
	}
	g.turnedOff = make(map[winipcfg.AddressFamily]guardBinding)
}

func (g *outboundGuard) restoreBindingLocked(family winipcfg.AddressFamily, binding guardBinding) {
	row, err := binding.luid.IPInterface(family)
	if err == nil {
		err = setWeakHostSend(row, true)
	}
	if err != nil {
		errors.LogWarningInner(context.Background(), err, "[tun] unable to turn weak host send on again for ", familyName(family), " on ", binding.name)
	}
}

func setWeakHostSend(row *winipcfg.MibIPInterfaceRow, on bool) error {
	row.WeakHostSend = on
	if row.Family == windows.AF_INET {
		row.SitePrefixLength = 0
	}
	return row.Set()
}

func familyName(family winipcfg.AddressFamily) string {
	if family == windows.AF_INET {
		return "IPv4"
	}
	return "IPv6"
}
