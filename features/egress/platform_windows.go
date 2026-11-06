//go:build windows

package egress

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func platformSupported() bool { return true }

func collect(Options) (Observation, error) {
	observation := Observation{IPv4Supported: true, IPv6Supported: true}
	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagDefault)
	if err != nil {
		observation.Error = "read adapter table: " + err.Error()
		return observation, err
	}

	adapterByLUID := make(map[string]int, len(adapters))
	for _, adapter := range adapters {
		luid := strconv.FormatUint(uint64(adapter.LUID), 10)
		adapterByLUID[luid] = len(observation.Adapters)
		observation.Adapters = append(observation.Adapters, AdapterObservation{
			Interface: Interface{
				Name:      adapter.FriendlyName(),
				Index:     adapter.IfIndex,
				IPv6Index: adapter.IPv6IfIndex,
				LUID:      luid,
			},
			Up:       adapter.OperStatus == winipcfg.IfOperStatusUp,
			Loopback: adapter.IfType == winipcfg.IfTypeSoftwareLoopback,
		})
	}

	addressRows, addressErr := winipcfg.GetUnicastIPAddressTable(windows.AF_UNSPEC)
	if addressErr != nil {
		observation.Error = "read interface address table: " + addressErr.Error()
		return observation, addressErr
	}
	for _, row := range addressRows {
		index, ok := adapterByLUID[strconv.FormatUint(uint64(row.InterfaceLUID), 10)]
		if !ok {
			continue
		}
		address := row.Address.Addr()
		if row.DadState != winipcfg.DadStatePreferred && row.DadState != winipcfg.DadStateDeprecated {
			continue
		}
		if !usableSourceAddress(address) {
			continue
		}
		prefix := netip.PrefixFrom(address, int(row.OnLinkPrefixLength))
		observation.Adapters[index].Interface.Addresses = append(observation.Adapters[index].Interface.Addresses, prefix.String())
	}
	for index := range observation.Adapters {
		addresses := observation.Adapters[index].Interface.Addresses
		sort.Strings(addresses)
	}

	collectFamily := func(family string, addressFamily winipcfg.AddressFamily) {
		interfaceRows, interfaceErr := winipcfg.GetIPInterfaceTable(addressFamily)
		if family == "ipv4" {
			if interfaceErr != nil {
				observation.IPv4Error = "read IPv4 interface metrics: " + interfaceErr.Error()
				return
			}
		} else if interfaceErr != nil {
			observation.IPv6Error = "read IPv6 interface metrics: " + interfaceErr.Error()
			return
		}
		metricByLUID := make(map[string]uint32, len(interfaceRows))
		for _, row := range interfaceRows {
			metricByLUID[strconv.FormatUint(uint64(row.InterfaceLUID), 10)] = row.Metric
		}
		for index := range observation.Adapters {
			metric, ok := metricByLUID[observation.Adapters[index].Interface.LUID]
			if !ok {
				continue
			}
			if family == "ipv4" {
				observation.Adapters[index].IPv4Metric = metric
			} else {
				observation.Adapters[index].IPv6Metric = metric
			}
		}

		routes, routeErr := winipcfg.GetIPForwardTable2(addressFamily)
		if routeErr != nil {
			if family == "ipv4" {
				observation.IPv4Error = "read IPv4 route table: " + routeErr.Error()
			} else {
				observation.IPv6Error = "read IPv6 route table: " + routeErr.Error()
			}
			return
		}
		for _, route := range routes {
			observation.Routes = append(observation.Routes, RouteObservation{
				Family:      family,
				LUID:        strconv.FormatUint(uint64(route.InterfaceLUID), 10),
				Destination: route.DestinationPrefix.Prefix(),
				Metric:      route.Metric,
			})
		}
	}
	collectFamily("ipv4", windows.AF_INET)
	collectFamily("ipv6", windows.AF_INET6)

	if observation.IPv4Error == "" || observation.IPv6Error == "" {
		observation.ObservedAt = time.Now().UTC()
	} else {
		observation.Error = fmt.Sprintf("IPv4 and IPv6 route snapshots are unavailable: %s; %s", observation.IPv4Error, observation.IPv6Error)
	}
	return observation, nil
}

func registerNotifications(refresh func()) (func(), error) {
	var routeCallback *winipcfg.RouteChangeCallback
	var interfaceCallback *winipcfg.InterfaceChangeCallback
	var addressCallback *winipcfg.UnicastAddressChangeCallback
	var firstErr error

	routeCallback, err := winipcfg.RegisterRouteChangeCallback(func(winipcfg.MibNotificationType, *winipcfg.MibIPforwardRow2) {
		refresh()
	})
	if err != nil {
		firstErr = err
	}
	interfaceCallback, err = winipcfg.RegisterInterfaceChangeCallback(func(winipcfg.MibNotificationType, *winipcfg.MibIPInterfaceRow) {
		refresh()
	})
	if err != nil && firstErr == nil {
		firstErr = err
	}
	addressCallback, err = winipcfg.RegisterUnicastAddressChangeCallback(func(winipcfg.MibNotificationType, *winipcfg.MibUnicastIPAddressRow) {
		refresh()
	})
	if err != nil && firstErr == nil {
		firstErr = err
	}
	cleanup := func() {
		if routeCallback != nil {
			_ = routeCallback.Unregister()
		}
		if interfaceCallback != nil {
			interfaceCallback.Unregister()
		}
		if addressCallback != nil {
			_ = addressCallback.Unregister()
		}
	}
	return cleanup, firstErr
}
