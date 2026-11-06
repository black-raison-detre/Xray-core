package egress

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func TestSelectAutoUsesFamilyDefaultRouteAndCombinedMetrics(t *testing.T) {
	observation := testObservation()
	snapshot := Select(observation, Options{}, false)
	if snapshot.State != "preview" || snapshot.Mode != "auto" {
		t.Fatalf("unexpected snapshot state: %+v", snapshot)
	}
	if snapshot.IPv4.Interface == nil || snapshot.IPv4.Interface.Name != "Ethernet" {
		t.Fatalf("IPv4 selected %v; want Ethernet", snapshot.IPv4.Interface)
	}
	if snapshot.IPv4.RouteMetric != 10 || snapshot.IPv4.InterfaceMetric != 5 {
		t.Fatalf("IPv4 metrics = (%d, %d); want (10, 5)", snapshot.IPv4.RouteMetric, snapshot.IPv4.InterfaceMetric)
	}
	if snapshot.IPv6.Interface == nil || snapshot.IPv6.Interface.Name != "Wi-Fi" {
		t.Fatalf("IPv6 selected %v; want Wi-Fi", snapshot.IPv6.Interface)
	}
	if snapshot.IPv6.RouteMetric != 3 || snapshot.IPv6.InterfaceMetric != 2 {
		t.Fatalf("IPv6 metrics = (%d, %d); want (3, 2)", snapshot.IPv6.RouteMetric, snapshot.IPv6.InterfaceMetric)
	}
	if snapshot.IPv4.State != "detected" || snapshot.IPv6.State != "detected" {
		t.Fatalf("preview family states = %q/%q; want detected/detected", snapshot.IPv4.State, snapshot.IPv6.State)
	}
}

func TestSelectFixedPreservesConfiguredAdapter(t *testing.T) {
	snapshot := Select(testObservation(), Options{InterfaceName: "wi-fi"}, true)
	if snapshot.Mode != "fixed" || snapshot.ConfiguredInterface != "wi-fi" {
		t.Fatalf("unexpected fixed-mode metadata: %+v", snapshot)
	}
	if snapshot.IPv4.Interface == nil || snapshot.IPv4.Interface.Name != "Wi-Fi" {
		t.Fatalf("IPv4 selected %v; want configured Wi-Fi", snapshot.IPv4.Interface)
	}
	if snapshot.IPv6.Interface == nil || snapshot.IPv6.Interface.Name != "Wi-Fi" {
		t.Fatalf("IPv6 selected %v; want configured Wi-Fi", snapshot.IPv6.Interface)
	}
	if snapshot.IPv4.State != "selected" || snapshot.IPv6.State != "selected" {
		t.Fatalf("active family states = %q/%q; want selected/selected", snapshot.IPv4.State, snapshot.IPv6.State)
	}
	for _, candidate := range snapshot.Candidates {
		if candidate.Interface.Name == "Ethernet" && candidate.Eligible {
			t.Errorf("non-configured adapter was eligible in fixed mode: %+v", candidate)
		}
	}
	if snapshot.IPv6.Interface.Index != 12 || snapshot.IPv6.Interface.IPv6Index != 22 {
		t.Fatalf("family indices were not preserved: %+v", snapshot.IPv6.Interface)
	}

	missing := Select(testObservation(), Options{InterfaceName: "missing"}, false)
	if missing.IPv4.Interface != nil || missing.IPv4.State != "unavailable" {
		t.Fatalf("missing fixed interface fell back to auto selection: %+v", missing.IPv4)
	}
}

func TestFixedSelectionDoesNotRequireAnObservedDefaultRoute(t *testing.T) {
	observation := testObservation()
	observation.Routes = nil
	snapshot := Select(observation, Options{InterfaceName: "Wi-Fi"}, true)
	if snapshot.IPv4.State != "selected" || snapshot.IPv4.Interface == nil || snapshot.IPv4.Interface.Name != "Wi-Fi" {
		t.Fatalf("fixed adapter was replaced without a default route: %+v", snapshot.IPv4)
	}
	if snapshot.IPv4.RouteMetric != 0 || snapshot.IPv4.InterfaceMetric != 0 {
		t.Fatalf("reported unavailable route metrics as real metrics: %+v", snapshot.IPv4)
	}
	if !strings.Contains(snapshot.IPv4.Reason, "no default route metric") {
		t.Fatalf("missing route-metric explanation: %q", snapshot.IPv4.Reason)
	}
}

func TestSelectExcludesTunLoopbackAndDownAdapters(t *testing.T) {
	observation := testObservation()
	observation.Adapters = append(
		observation.Adapters,
		AdapterObservation{Interface: Interface{Name: "Xray-GUI TUN", Index: 50, IPv6Index: 60, LUID: "tun"}, Up: true},
		AdapterObservation{Interface: Interface{Name: "Loopback", Index: 70, IPv6Index: 80, LUID: "loop"}, Up: true, Loopback: true},
		AdapterObservation{Interface: Interface{Name: "Disconnected", Index: 90, IPv6Index: 100, LUID: "down"}, Up: false},
	)
	observation.Routes = append(
		observation.Routes,
		defaultRoute("ipv4", "tun", "0.0.0.0/0", 0),
		defaultRoute("ipv6", "tun", "::/0", 0),
		defaultRoute("ipv4", "loop", "0.0.0.0/0", 0),
		defaultRoute("ipv4", "down", "0.0.0.0/0", 0),
	)
	snapshot := Select(observation, Options{TunIndex: 50, TunName: "Xray-GUI TUN"}, false)
	if snapshot.IPv4.Interface == nil || snapshot.IPv4.Interface.Name != "Ethernet" {
		t.Fatalf("IPv4 selected ineligible interface %v", snapshot.IPv4.Interface)
	}
	for _, candidate := range snapshot.Candidates {
		if candidate.Interface.Name == "Xray-GUI TUN" || candidate.Interface.Name == "Loopback" || candidate.Interface.Name == "Disconnected" {
			if candidate.Eligible {
				t.Errorf("ineligible adapter %q was marked eligible", candidate.Interface.Name)
			}
		}
	}
}

func TestUnavailableIPv6DoesNotBreakIPv4(t *testing.T) {
	observation := testObservation()
	observation.IPv6Supported = false
	snapshot := Select(observation, Options{}, false)
	if snapshot.IPv4.Interface == nil || snapshot.IPv4.State != "detected" {
		t.Fatalf("IPv4 selection was lost: %+v", snapshot.IPv4)
	}
	if snapshot.IPv6.State != "unsupported" {
		t.Fatalf("IPv6 state = %q; want unsupported", snapshot.IPv6.State)
	}
}

func TestAutoSelectionRejectsWrongFamilyOnlyAdapter(t *testing.T) {
	observation := testObservation()
	observation.Adapters[1].IPv6Metric = 0
	for index := range observation.Routes {
		if observation.Routes[index].Family == "ipv6" && observation.Routes[index].LUID == "ethernet" {
			observation.Routes[index].Metric = 0
		}
	}
	snapshot := Select(observation, Options{}, false)
	if snapshot.IPv6.Interface == nil || snapshot.IPv6.Interface.Name != "Wi-Fi" {
		t.Fatalf("IPv6 selected adapter without a usable IPv6 address: %+v", snapshot.IPv6)
	}
	for _, candidate := range snapshot.Candidates {
		if candidate.Family == "ipv6" && candidate.Interface.Name == "Ethernet" {
			if candidate.Eligible || !strings.Contains(strings.Join(candidate.Reasons, " "), "no usable IPv6 unicast address") {
				t.Fatalf("wrong-family adapter candidate = %+v", candidate)
			}
		}
	}
}

func TestFixedFamilyWithRemovedAddressBecomesUnavailable(t *testing.T) {
	observation := testObservation()
	previous := Select(observation, Options{InterfaceName: "Wi-Fi"}, true)
	observation.Adapters[0].Interface.Addresses = []string{"2001:db8::10/64"}
	snapshot := Select(observation, Options{InterfaceName: "Wi-Fi"}, true)
	if snapshot.IPv4.State != "unavailable" || snapshot.IPv4.Interface != nil {
		t.Fatalf("fixed IPv4 binding remained selected after address removal: %+v", snapshot.IPv4)
	}
	if snapshot.IPv6.State != "selected" || snapshot.IPv6.Interface == nil || snapshot.IPv6.Interface.Name != "Wi-Fi" {
		t.Fatalf("usable IPv6 fixed binding was affected by IPv4 address removal: %+v", snapshot.IPv6)
	}
	if selectionSignature(previous) == selectionSignature(snapshot) {
		t.Fatal("address removal did not change the active selection signature")
	}
}

func TestSelectRejectsNonUplinkAddressKinds(t *testing.T) {
	observation := testObservation()
	observation.Adapters[0].Interface.Addresses = []string{"127.0.0.1/8", "fe80::1/64", "ff02::1/128"}
	observation.Adapters[1].Interface.Addresses = []string{"0.0.0.0/0"}
	snapshot := Select(observation, Options{}, false)
	if snapshot.IPv4.State != "unavailable" || snapshot.IPv4.Interface != nil {
		t.Fatalf("IPv4 selected an adapter without an uplink unicast source: %+v", snapshot.IPv4)
	}
	if snapshot.IPv6.State != "unavailable" || snapshot.IPv6.Interface != nil {
		t.Fatalf("IPv6 selected an adapter without an uplink unicast source: %+v", snapshot.IPv6)
	}
}

func TestSnapshotOmitsUnavailableObservationTime(t *testing.T) {
	encoded, err := json.Marshal(inactiveSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "0001-01-01") {
		t.Fatalf("zero observation time was exposed as current status: %s", encoded)
	}
}

func testObservation() Observation {
	return Observation{
		IPv4Supported: true,
		IPv6Supported: true,
		Adapters: []AdapterObservation{
			{
				Interface:  Interface{Name: "Wi-Fi", Index: 12, IPv6Index: 22, LUID: "wifi", Addresses: []string{"192.0.2.10/24", "2001:db8::10/64"}},
				Up:         true,
				IPv4Metric: 20,
				IPv6Metric: 2,
			},
			{
				Interface:  Interface{Name: "Ethernet", Index: 33, IPv6Index: 44, LUID: "ethernet", Addresses: []string{"198.51.100.10/24"}},
				Up:         true,
				IPv4Metric: 5,
				IPv6Metric: 30,
			},
		},
		Routes: []RouteObservation{
			defaultRoute("ipv4", "wifi", "0.0.0.0/0", 1),
			defaultRoute("ipv4", "ethernet", "0.0.0.0/0", 10),
			defaultRoute("ipv6", "wifi", "::/0", 3),
			defaultRoute("ipv6", "ethernet", "::/0", 1),
		},
	}
}

func defaultRoute(family, luid, prefix string, metric uint32) RouteObservation {
	return RouteObservation{Family: family, LUID: luid, Destination: netip.MustParsePrefix(prefix), Metric: metric}
}
