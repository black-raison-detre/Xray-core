package tun

import (
	"net/netip"

	"github.com/xtls/xray-core/features/egress"
)

type tunDNSPlan struct {
	generation uint64
	ipv4       []netip.Addr
	ipv6       []netip.Addr
}

func planTUNAdapterDNS(snapshot *egress.Snapshot) tunDNSPlan {
	generation, ipv4, ipv6 := egress.PlanDNSForTUN(snapshot)
	return tunDNSPlan{generation: generation, ipv4: ipv4, ipv6: ipv6}
}

func equalTUNDNSPlan(left, right *tunDNSPlan) bool {
	if left == nil || right == nil || left.generation != right.generation || len(left.ipv4) != len(right.ipv4) || len(left.ipv6) != len(right.ipv6) {
		return left == nil && right == nil
	}
	for index := range left.ipv4 {
		if left.ipv4[index] != right.ipv4[index] {
			return false
		}
	}
	for index := range left.ipv6 {
		if left.ipv6[index] != right.ipv6[index] {
			return false
		}
	}
	return true
}
