package dns

import "context"

const DNSResolveTraceCapability = "dns-resolve-trace-v1"

// LookupTrace contains details observed while one request follows the active
// DNS policy. It is intentionally separate from Client so existing DNS
// clients do not need to implement diagnostic tracing.
type LookupTrace struct {
	QueryName    string
	ResolvedName string
	HostsStatus  string
	Aliases      []string
	Strategy     string
	Fallback     string
	Resolvers    []ResolverTrace
	Answers      []string
	TTL          uint32
}

// ResolverTrace describes one selected resolver attempt in policy order.
type ResolverTrace struct {
	Index        uint32
	Name         string
	MatchedRules []string
	Selection    string
	Status       string
	Answers      []string
	Error        string
	LatencyMs    int64
}

// TraceClient is an optional capability implemented by the managed DNS
// feature. The caller's context applies only to this lookup.
type TraceClient interface {
	LookupIPWithTrace(context.Context, string, IPOption) (LookupTrace, error)
}
