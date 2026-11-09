package egress

import (
	"net/netip"
	"strings"
)

const (
	// NetworkRecoveryCapability identifies a core build with live TUN egress
	// and adapter DNS recovery support.
	NetworkRecoveryCapability = "tun-network-recovery-v1"

	// SystemEgressDNSAddress opts into DNS servers from the active selected
	// physical adapter. It is a configuration sentinel, not a DNS hostname.
	SystemEgressDNSAddress = "system+egress"
	AdapterDNSUpdateError  = "tun_adapter_dns_update_failed:"

	TUNPeerDNSIPv4 = "172.31.255.2"
	TUNPeerDNSIPv6 = "fd78:7261:7947::2"
)

// DNSForFamily returns the numeric DNS servers recorded for the currently
// selected interface of family. It intentionally does not consult the host
// resolver or fall back to another adapter.
func DNSForFamily(snapshot *Snapshot, family string) (luid string, servers []string) {
	if snapshot == nil || snapshot.State != "active" {
		return "", nil
	}
	var status FamilyStatus
	switch family {
	case "ipv4":
		status = snapshot.IPv4
	case "ipv6":
		status = snapshot.IPv6
	default:
		return "", nil
	}
	if status.State != "selected" || status.Interface == nil {
		return "", nil
	}
	luid = status.Interface.LUID
	for _, server := range status.Interface.DNSServers {
		address, err := netip.ParseAddr(server)
		if err != nil || !usableDNSServer(address) {
			continue
		}
		address = address.Unmap()
		if (family == "ipv4" && !address.Is4()) || (family == "ipv6" && !address.Is6()) {
			continue
		}
		servers = append(servers, address.String())
	}
	return luid, servers
}

func usableDNSServer(address netip.Addr) bool {
	return address.IsValid() && address.IsGlobalUnicast() && !address.IsLinkLocalUnicast()
}

// PlanDNSForTUN returns DNS addresses for the selected physical adapter of
// each family. A sticky adapter-DNS programming fault retains the last
// observed selection for retries; other unavailable/error snapshots clear it.
func PlanDNSForTUN(snapshot *Snapshot) (generation uint64, ipv4, ipv6 []netip.Addr) {
	if snapshot == nil {
		return 0, nil, nil
	}
	if snapshot.State != "active" && !(snapshot.State == "error" && strings.HasPrefix(snapshot.Error, AdapterDNSUpdateError)) {
		return snapshot.Generation, nil, nil
	}
	_, ipv4 = DNSForFamilyIgnoringState(snapshot.IPv4, "ipv4")
	_, ipv6 = DNSForFamilyIgnoringState(snapshot.IPv6, "ipv6")
	return snapshot.Generation, ipv4, ipv6
}

// ReportAdapterDNSUpdateError publishes a sticky failure for the active TUN.
func ReportAdapterDNSUpdateError(err error) {
	if manager := getActiveManager(); manager != nil {
		manager.ReportAdapterDNSUpdateError(err)
	}
}

// ReportAdapterDNSUpdateSuccess clears a previously published adapter DNS
// failure after the active TUN's IPv4 and IPv6 settings are both applied.
func ReportAdapterDNSUpdateSuccess(generation uint64) {
	if manager := getActiveManager(); manager != nil {
		manager.ReportAdapterDNSUpdateSuccess(generation)
	}
}

// DNSUpdateSnapshot returns the active manager's physical selection for the
// app-owned TUN DNS updater, bypassing only its sticky fault redaction.
func DNSUpdateSnapshot() *Snapshot {
	if manager := getActiveManager(); manager != nil {
		return manager.DNSUpdateSnapshot()
	}
	return inactiveSnapshot()
}

func DNSForFamilyIgnoringState(status FamilyStatus, family string) (luid string, servers []netip.Addr) {
	if status.State != "selected" || status.Interface == nil {
		return "", nil
	}
	luid = status.Interface.LUID
	for _, server := range status.Interface.DNSServers {
		address, err := netip.ParseAddr(server)
		if err != nil || !usableDNSServer(address) {
			continue
		}
		address = address.Unmap()
		if (family == "ipv4" && !address.Is4()) || (family == "ipv6" && !address.Is6()) {
			continue
		}
		servers = append(servers, address)
	}
	return luid, servers
}
