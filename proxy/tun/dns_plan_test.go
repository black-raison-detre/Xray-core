package tun

import (
	"net/netip"
	"testing"

	"github.com/xtls/xray-core/features/egress"
)

func TestPlanTUNAdapterDNSUsesSelectedFamilyDNSAndClearsUnavailableFamily(t *testing.T) {
	snapshot := &egress.Snapshot{
		State:      "active",
		Generation: 4,
		IPv4: egress.FamilyStatus{State: "selected", Interface: &egress.Interface{
			LUID: "ethernet", DNSServers: []string{"192.0.2.53", "2001:db8::53", "127.0.0.53"},
		}},
		IPv6: egress.FamilyStatus{State: "unavailable", Reason: "no selected IPv6 adapter"},
	}
	plan := planTUNAdapterDNS(snapshot)
	if plan.generation != 4 || len(plan.ipv4) != 1 || plan.ipv4[0] != netip.MustParseAddr("192.0.2.53") || len(plan.ipv6) != 0 {
		t.Fatalf("TUN DNS plan = %+v", plan)
	}
}

func TestPlanTUNAdapterDNSRetainsCurrentSelectionForStickyFaultRetry(t *testing.T) {
	snapshot := &egress.Snapshot{
		State:      "error",
		Error:      egress.AdapterDNSUpdateError + "SetDNS failed",
		Generation: 8,
		IPv4: egress.FamilyStatus{State: "selected", Interface: &egress.Interface{
			LUID: "ethernet", DNSServers: []string{"192.0.2.54"},
		}},
		IPv6: egress.FamilyStatus{State: "unavailable"},
	}
	plan := planTUNAdapterDNS(snapshot)
	if plan.generation != 8 || len(plan.ipv4) != 1 || plan.ipv4[0] != netip.MustParseAddr("192.0.2.54") {
		t.Fatalf("sticky retry plan = %+v", plan)
	}
	if got := planTUNAdapterDNS(&egress.Snapshot{State: "error", Error: "route table unavailable", Generation: 9}); len(got.ipv4) != 0 || len(got.ipv6) != 0 {
		t.Fatalf("generic egress error retained stale TUN DNS: %+v", got)
	}
}

func TestEqualTUNDNSPlanIncludesGenerationAndFamilyLists(t *testing.T) {
	base := &tunDNSPlan{generation: 1, ipv4: []netip.Addr{netip.MustParseAddr("192.0.2.53")}}
	same := &tunDNSPlan{generation: 1, ipv4: []netip.Addr{netip.MustParseAddr("192.0.2.53")}}
	if !equalTUNDNSPlan(base, same) {
		t.Fatal("equal plans compared unequal")
	}
	if equalTUNDNSPlan(base, &tunDNSPlan{generation: 2, ipv4: same.ipv4}) {
		t.Fatal("generation change compared equal")
	}
	if equalTUNDNSPlan(base, &tunDNSPlan{generation: 1, ipv6: []netip.Addr{netip.MustParseAddr("2001:db8::53")}}) {
		t.Fatal("family change compared equal")
	}
}
