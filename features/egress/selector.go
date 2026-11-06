package egress

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

type routeChoice struct {
	metric          uint32
	interfaceMetric uint32
	total           uint64
	found           bool
}

// Select deterministically selects one default-route adapter for each
// supported family. It performs no operating-system writes and is also used
// to build active bindings from a fresh Windows route-table observation.
func Select(observation Observation, options Options, active bool) *Snapshot {
	options = normalizeOptions(options)
	state := "preview"
	if active {
		state = "active"
	}
	if observation.Unsupported != "" {
		state = "unsupported"
	} else if observation.Error != "" {
		state = "error"
	} else if !observation.IPv4Supported && !observation.IPv6Supported {
		state = "unavailable"
	}

	observedAt := observation.ObservedAt
	if observedAt.IsZero() && observation.Error == "" && observation.Unsupported == "" {
		observedAt = time.Now().UTC()
	}

	snapshot := &Snapshot{
		State:               state,
		Mode:                modeFor(options),
		ConfiguredInterface: configuredInterfaceFor(options),
		ObservedAt:          observedAt,
		IPv4:                selectFamily(observation, options, "ipv4", active),
		IPv6:                selectFamily(observation, options, "ipv6", active),
		Candidates:          make([]Candidate, 0, len(observation.Adapters)*2),
		Error:               observation.Error,
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		if !familySupported(observation, family) {
			continue
		}
		for _, adapter := range observation.Adapters {
			candidate := makeCandidate(observation, options, family, adapter)
			snapshot.Candidates = append(snapshot.Candidates, candidate)
		}
	}
	sort.Slice(snapshot.Candidates, func(i, j int) bool {
		if snapshot.Candidates[i].Family != snapshot.Candidates[j].Family {
			return snapshot.Candidates[i].Family < snapshot.Candidates[j].Family
		}
		left, right := snapshot.Candidates[i].Interface, snapshot.Candidates[j].Interface
		if !strings.EqualFold(left.Name, right.Name) {
			return strings.ToLower(left.Name) < strings.ToLower(right.Name)
		}
		return left.LUID < right.LUID
	})
	return snapshot
}

func selectFamily(observation Observation, options Options, family string, active bool) FamilyStatus {
	if observation.Unsupported != "" {
		return FamilyStatus{State: "unsupported", Reason: observation.Unsupported}
	}
	if !familySupported(observation, family) {
		reason := "address family is not supported"
		if family == "ipv4" && observation.IPv4Error != "" {
			reason = observation.IPv4Error
		} else if family == "ipv6" && observation.IPv6Error != "" {
			reason = observation.IPv6Error
		}
		return FamilyStatus{State: "unsupported", Reason: reason}
	}
	if family == "ipv4" && observation.IPv4Error != "" {
		return FamilyStatus{State: "unavailable", Reason: observation.IPv4Error}
	}
	if family == "ipv6" && observation.IPv6Error != "" {
		return FamilyStatus{State: "unavailable", Reason: observation.IPv6Error}
	}

	if options.InterfaceName != "" {
		for _, adapter := range observation.Adapters {
			if !strings.EqualFold(adapter.Interface.Name, options.InterfaceName) {
				continue
			}
			if reason := baseIneligibility(options, family, adapter); reason != "" {
				return FamilyStatus{State: "unavailable", Reason: "configured interface " + adapter.Interface.Name + " " + reason}
			}
			route := bestDefaultRoute(observation, family, adapter)
			status := FamilyStatus{
				State:     familySelectedState(active),
				Interface: copyInterface(&adapter.Interface),
			}
			if route.found {
				status.RouteMetric = route.metric
				status.InterfaceMetric = route.interfaceMetric
				status.Reason = fmt.Sprintf("fixed interface; route metric %d plus interface metric %d", route.metric, route.interfaceMetric)
			} else {
				status.Reason = "fixed interface; no default route metric is available"
			}
			return status
		}
		return FamilyStatus{State: "unavailable", Reason: "configured interface " + options.InterfaceName + " was not found"}
	}

	var best *AdapterObservation
	var bestRoute routeChoice
	for i := range observation.Adapters {
		adapter := &observation.Adapters[i]
		if reason := baseIneligibility(options, family, *adapter); reason != "" {
			continue
		}
		route := bestDefaultRoute(observation, family, *adapter)
		if !route.found {
			continue
		}
		if best == nil || routeBefore(route, adapter, bestRoute, best) {
			best = adapter
			bestRoute = route
		}
	}
	if best == nil {
		return FamilyStatus{State: "unavailable", Reason: "no eligible default-route interface was observed"}
	}
	return FamilyStatus{
		State:           familySelectedState(active),
		Interface:       copyInterface(&best.Interface),
		Reason:          fmt.Sprintf("lowest observed default-route cost: route metric %d plus interface metric %d", bestRoute.metric, bestRoute.interfaceMetric),
		RouteMetric:     bestRoute.metric,
		InterfaceMetric: bestRoute.interfaceMetric,
	}
}

func makeCandidate(observation Observation, options Options, family string, adapter AdapterObservation) Candidate {
	route := bestDefaultRoute(observation, family, adapter)
	reasons := make([]string, 0, 4)
	if options.InterfaceName != "" && !strings.EqualFold(options.InterfaceName, adapter.Interface.Name) {
		reasons = append(reasons, "not the configured fixed interface")
	}
	if reason := baseIneligibility(options, family, adapter); reason != "" {
		reasons = append(reasons, reason)
	} else if options.InterfaceName == "" && !route.found {
		reasons = append(reasons, "no default route observed")
	}
	return Candidate{
		Family:          family,
		Interface:       copyInterface(&adapter.Interface),
		Eligible:        len(reasons) == 0,
		Reasons:         reasons,
		RouteMetric:     route.metric,
		InterfaceMetric: route.interfaceMetric,
	}
}

func baseIneligibility(options Options, family string, adapter AdapterObservation) string {
	if !adapter.Up {
		return "is down"
	}
	if adapter.Loopback {
		return "is loopback"
	}
	if (options.TunIndex != 0 && adapter.Interface.Index == options.TunIndex) ||
		(options.TunName != "" && strings.EqualFold(adapter.Interface.Name, options.TunName)) {
		return "is the app-owned TUN interface"
	}
	for _, name := range options.ExcludedInterfaces {
		if strings.EqualFold(strings.TrimSpace(name), adapter.Interface.Name) {
			return "is excluded"
		}
	}
	if family == "ipv4" && adapter.Interface.Index == 0 {
		return "has no IPv4 interface index"
	}
	if family == "ipv6" && adapter.Interface.IPv6Index == 0 {
		return "has no IPv6 interface index"
	}
	if !hasUsableFamilyAddress(adapter.Interface, family) {
		familyName := "IPv4"
		if family == "ipv6" {
			familyName = "IPv6"
		}
		return "has no usable " + familyName + " unicast address"
	}
	return ""
}

func hasUsableFamilyAddress(iface Interface, family string) bool {
	for _, addressText := range iface.Addresses {
		var address netip.Addr
		if prefix, err := netip.ParsePrefix(addressText); err == nil {
			address = prefix.Addr()
		} else if addressValue, err := netip.ParseAddr(addressText); err == nil {
			address = addressValue
		}
		if family == "ipv4" && address.Is4() && usableSourceAddress(address) {
			return true
		}
		if family == "ipv6" && address.Is6() && usableSourceAddress(address) {
			return true
		}
	}
	return false
}

func usableSourceAddress(address netip.Addr) bool {
	return address.IsValid() && address.IsGlobalUnicast() && !address.IsLinkLocalUnicast()
}

func bestDefaultRoute(observation Observation, family string, adapter AdapterObservation) routeChoice {
	interfaceMetric := adapter.IPv4Metric
	if family == "ipv6" {
		interfaceMetric = adapter.IPv6Metric
	}
	var best routeChoice
	for _, route := range observation.Routes {
		if route.Family != family || route.LUID != adapter.Interface.LUID || !isDefaultRoute(route, family) {
			continue
		}
		total := uint64(route.Metric) + uint64(interfaceMetric)
		if !best.found || total < best.total || (total == best.total && route.Metric < best.metric) {
			best = routeChoice{metric: route.Metric, interfaceMetric: interfaceMetric, total: total, found: true}
		}
	}
	return best
}

func isDefaultRoute(route RouteObservation, family string) bool {
	if !route.Destination.IsValid() || route.Destination.Bits() != 0 {
		return false
	}
	return family == "ipv4" && route.Destination.Addr().Is4() || family == "ipv6" && route.Destination.Addr().Is6()
}

func routeBefore(left routeChoice, leftAdapter *AdapterObservation, right routeChoice, rightAdapter *AdapterObservation) bool {
	if left.total != right.total {
		return left.total < right.total
	}
	leftName, rightName := strings.ToLower(leftAdapter.Interface.Name), strings.ToLower(rightAdapter.Interface.Name)
	if leftName != rightName {
		return leftName < rightName
	}
	return leftAdapter.Interface.LUID < rightAdapter.Interface.LUID
}

func familySelectedState(active bool) string {
	if active {
		return "selected"
	}
	return "detected"
}

func familySupported(observation Observation, family string) bool {
	if family == "ipv4" {
		return observation.IPv4Supported
	}
	return observation.IPv6Supported
}

func copyInterface(iface *Interface) *Interface {
	if iface == nil {
		return nil
	}
	copy := *iface
	copy.Addresses = append([]string(nil), iface.Addresses...)
	return &copy
}

func cloneSnapshot(snapshot *Snapshot) *Snapshot {
	if snapshot == nil {
		return inactiveSnapshot()
	}
	copy := *snapshot
	copy.IPv4.Interface = copyInterface(snapshot.IPv4.Interface)
	copy.IPv6.Interface = copyInterface(snapshot.IPv6.Interface)
	copy.Candidates = make([]Candidate, len(snapshot.Candidates))
	for i, candidate := range snapshot.Candidates {
		copy.Candidates[i] = candidate
		copy.Candidates[i].Interface = copyInterface(candidate.Interface)
		copy.Candidates[i].Reasons = append([]string(nil), candidate.Reasons...)
	}
	return &copy
}
