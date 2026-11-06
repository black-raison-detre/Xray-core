package egress

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"time"
)

// Options control egress selection. An empty InterfaceName or "auto" selects
// the lowest-metric default-route adapter independently for each address
// family. A non-empty name selects that adapter for both families.
type Options struct {
	InterfaceName      string
	ExcludedInterfaces []string
	TunIndex           uint32
	TunName            string
}

// Interface is a stable adapter identity and the family-specific indices used
// when binding sockets on Windows.
type Interface struct {
	Name      string   `json:"name"`
	Index     uint32   `json:"index"`
	IPv6Index uint32   `json:"ipv6Index"`
	LUID      string   `json:"luid"`
	Addresses []string `json:"addresses"`
}

// FamilyStatus describes the selected or detected adapter for one address
// family. Metrics are zero when the configured fixed adapter has no matching
// default route in the observed route table.
type FamilyStatus struct {
	State           string     `json:"state"`
	Interface       *Interface `json:"interface,omitempty"`
	Reason          string     `json:"reason,omitempty"`
	RouteMetric     uint32     `json:"routeMetric"`
	InterfaceMetric uint32     `json:"interfaceMetric"`
}

// Candidate describes one adapter's eligibility and default-route metrics for
// one address family. One adapter can produce separate IPv4 and IPv6 rows.
type Candidate struct {
	Family          string     `json:"family"`
	Interface       *Interface `json:"interface"`
	Eligible        bool       `json:"eligible"`
	Reasons         []string   `json:"reasons,omitempty"`
	RouteMetric     uint32     `json:"routeMetric"`
	InterfaceMetric uint32     `json:"interfaceMetric"`
}

// Snapshot is the read-only egress state shared by the API, CLI preflight and
// active socket binding updater.
type Snapshot struct {
	State               string       `json:"state"`
	Mode                string       `json:"mode"`
	ConfiguredInterface string       `json:"configuredInterface"`
	Generation          uint64       `json:"generation"`
	ObservedAt          time.Time    `json:"observedAt"`
	IPv4                FamilyStatus `json:"ipv4"`
	IPv6                FamilyStatus `json:"ipv6"`
	Candidates          []Candidate  `json:"candidates"`
	Error               string       `json:"error,omitempty"`
}

func (snapshot Snapshot) MarshalJSON() ([]byte, error) {
	type snapshotJSON struct {
		State               string       `json:"state"`
		Mode                string       `json:"mode"`
		ConfiguredInterface string       `json:"configuredInterface"`
		Generation          uint64       `json:"generation"`
		ObservedAt          *time.Time   `json:"observedAt,omitempty"`
		IPv4                FamilyStatus `json:"ipv4"`
		IPv6                FamilyStatus `json:"ipv6"`
		Candidates          []Candidate  `json:"candidates"`
		Error               string       `json:"error,omitempty"`
	}
	var observedAt *time.Time
	if !snapshot.ObservedAt.IsZero() {
		observedAt = &snapshot.ObservedAt
	}
	return json.Marshal(snapshotJSON{
		State:               snapshot.State,
		Mode:                snapshot.Mode,
		ConfiguredInterface: snapshot.ConfiguredInterface,
		Generation:          snapshot.Generation,
		ObservedAt:          observedAt,
		IPv4:                snapshot.IPv4,
		IPv6:                snapshot.IPv6,
		Candidates:          snapshot.Candidates,
		Error:               snapshot.Error,
	})
}

// Request contains the read-only egress status query options.
type Request struct {
	Preview            bool
	Refresh            bool
	InterfaceName      string
	ExcludedInterfaces []string
}

// AdapterObservation is a platform-neutral adapter row consumed by the pure
// selector and its deterministic tests.
type AdapterObservation struct {
	Interface  Interface
	Up         bool
	Loopback   bool
	IPv4Metric uint32
	IPv6Metric uint32
}

// RouteObservation is a platform-neutral route row. Metric is the route's
// own metric; the selector adds the matching family interface metric.
type RouteObservation struct {
	Family      string
	LUID        string
	Destination netip.Prefix
	Metric      uint32
}

// Observation is a single OS snapshot. Family errors are isolated so an
// unavailable IPv6 table never prevents a usable IPv4 result.
type Observation struct {
	Adapters      []AdapterObservation
	Routes        []RouteObservation
	IPv4Supported bool
	IPv6Supported bool
	IPv4Error     string
	IPv6Error     string
	Error         string
	ObservedAt    time.Time
	Unsupported   string
}

// Preview runs the same selector used by an active TUN binding and reports
// detected adapter choices without changing system networking state.
func Preview(options Options) *Snapshot {
	options = normalizeOptions(options)
	observation, err := collect(options)
	if err != nil && observation.Error == "" {
		observation.Error = err.Error()
	}
	return Select(observation, options, false)
}

// Status returns a preview or a copy of the current active selection. For an
// active request with Refresh set, it waits briefly for the updater to publish
// a fresh OS snapshot.
func Status(ctx context.Context, request Request) *Snapshot {
	if request.Preview {
		return Preview(Options{
			InterfaceName:      request.InterfaceName,
			ExcludedInterfaces: request.ExcludedInterfaces,
		})
	}

	current := getActiveManager()
	if current == nil {
		return inactiveSnapshot()
	}
	if request.Refresh {
		current.Refresh(ctx)
	}
	return current.Snapshot()
}

func normalizeOptions(options Options) Options {
	options.InterfaceName = strings.TrimSpace(options.InterfaceName)
	if options.InterfaceName == "" || strings.EqualFold(options.InterfaceName, "auto") {
		options.InterfaceName = ""
	}
	options.ExcludedInterfaces = append([]string(nil), options.ExcludedInterfaces...)
	return options
}

func modeFor(options Options) string {
	if options.InterfaceName == "" {
		return "auto"
	}
	return "fixed"
}

func configuredInterfaceFor(options Options) string {
	if options.InterfaceName == "" {
		return "auto"
	}
	return options.InterfaceName
}

func inactiveSnapshot() *Snapshot {
	if !platformSupported() {
		return &Snapshot{
			State:               "unsupported",
			Mode:                "auto",
			ConfiguredInterface: "auto",
			IPv4:                FamilyStatus{State: "unsupported", Reason: "automatic adapter selection is only available on Windows"},
			IPv6:                FamilyStatus{State: "unsupported", Reason: "automatic adapter selection is only available on Windows"},
			Candidates:          []Candidate{},
		}
	}
	return &Snapshot{
		State:               "inactive",
		Mode:                "auto",
		ConfiguredInterface: "auto",
		IPv4:                FamilyStatus{State: "unavailable", Reason: "TUN egress binding is not active"},
		IPv6:                FamilyStatus{State: "unavailable", Reason: "TUN egress binding is not active"},
		Candidates:          []Candidate{},
	}
}
