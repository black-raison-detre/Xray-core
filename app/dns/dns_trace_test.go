package dns

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	featureDNS "github.com/xtls/xray-core/features/dns"
)

type traceTestServer struct {
	name    string
	query   func(context.Context, string, featureDNS.IPOption) ([]net.IP, uint32, error)
	mu      sync.Mutex
	queries int
	domains []string
}

func (s *traceTestServer) Name() string       { return s.name }
func (*traceTestServer) IsDisableCache() bool { return true }
func (s *traceTestServer) QueryIP(ctx context.Context, domain string, option featureDNS.IPOption) ([]net.IP, uint32, error) {
	s.mu.Lock()
	s.queries++
	s.domains = append(s.domains, domain)
	s.mu.Unlock()
	return s.query(ctx, domain, option)
}

func newTraceTestDNS(t *testing.T, servers []*traceTestServer, hosts []*Config_HostMapping, parallel bool) *DNS {
	t.Helper()
	staticHosts, err := NewStaticHosts(hosts)
	if err != nil {
		t.Fatal(err)
	}
	option := &featureDNS.IPOption{IPv4Enable: true, IPv6Enable: true}
	clients := make([]*Client, len(servers))
	for index, server := range servers {
		clients[index] = &Client{
			server: server, timeoutMs: 2 * time.Second,
			ipOption: option,
		}
	}
	return &DNS{
		hosts: staticHosts, ipOption: option, clients: clients,
		ctx: context.Background(), enableParallelQuery: parallel,
	}
}

func fullDomainRule(domain string) *geodata.DomainRule {
	return &geodata.DomainRule{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{
		Type: geodata.Domain_Full, Value: domain,
	}}}
}

func TestLookupIPWithTraceReportsStaticAliasAndDoesNotQueryResolvers(t *testing.T) {
	dnsClient := newTraceTestDNS(t, []*traceTestServer{{name: "never-called"}}, []*Config_HostMapping{
		{Domain: fullDomainRule("alias.example"), ProxiedDomain: "target.example"},
		{Domain: fullDomainRule("target.example"), Ip: [][]byte{{192, 0, 2, 17}}},
	}, false)

	trace, err := dnsClient.LookupIPWithTrace(context.Background(), "alias.example.", featureDNS.IPOption{IPv4Enable: true})
	if err != nil {
		t.Fatal(err)
	}
	if trace.QueryName != "alias.example" || trace.ResolvedName != "target.example" || trace.HostsStatus != "alias-resolved" ||
		len(trace.Aliases) != 1 || trace.Aliases[0] != "alias.example -> target.example" ||
		len(trace.Answers) != 1 || trace.Answers[0] != "192.0.2.17" || trace.TTL != 10 || len(trace.Resolvers) != 0 {
		t.Fatalf("trace = %#v", trace)
	}
	dnsClient.clients[0].server.(*traceTestServer).mu.Lock()
	queries := dnsClient.clients[0].server.(*traceTestServer).queries
	dnsClient.clients[0].server.(*traceTestServer).mu.Unlock()
	if queries != 0 {
		t.Fatalf("static hosts lookup made %d resolver queries", queries)
	}
}

func TestLookupIPWithTraceReportsSerialFallbackAndRequestedFamily(t *testing.T) {
	first := &traceTestServer{name: "first", query: func(context.Context, string, featureDNS.IPOption) ([]net.IP, uint32, error) {
		return nil, 0, errors.New("resolver unavailable")
	}}
	second := &traceTestServer{name: "second", query: func(_ context.Context, _ string, option featureDNS.IPOption) ([]net.IP, uint32, error) {
		if !option.IPv6Enable || option.IPv4Enable {
			return nil, 0, errors.New("expected AAAA-only query")
		}
		return []net.IP{net.ParseIP("2001:db8::19")}, 77, nil
	}}
	dnsClient := newTraceTestDNS(t, []*traceTestServer{first, second}, nil, false)
	rule, err := geodata.ParseDomainRule("full:example.test", geodata.Domain_Full)
	if err != nil {
		t.Fatal(err)
	}
	dnsClient.domainMatcher, err = geodata.DomainReg.BuildDomainMatcher([]*geodata.DomainRule{rule})
	if err != nil {
		t.Fatal(err)
	}
	dnsClient.matcherInfos = []*DomainMatcherInfo{{clientIdx: 0, domainRule: rule.String()}}

	trace, err := dnsClient.LookupIPWithTrace(context.Background(), "example.test", featureDNS.IPOption{IPv6Enable: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(trace.Strategy, "IPv6 only") || trace.Fallback != "enabled" ||
		len(trace.Resolvers) != 2 || trace.Resolvers[0].Status != "error" || len(trace.Resolvers[0].MatchedRules) != 1 ||
		trace.Resolvers[0].Selection != "domain match" ||
		trace.Resolvers[1].Status != "winner" || trace.Resolvers[1].Selection != "fallback" ||
		trace.TTL != 77 || len(trace.Answers) != 1 || trace.Answers[0] != "2001:db8::19" {
		t.Fatalf("trace = %#v", trace)
	}
}

func TestLookupIPWithTraceMarksParallelLosersCancelled(t *testing.T) {
	fast := &traceTestServer{name: "fast", query: func(context.Context, string, featureDNS.IPOption) ([]net.IP, uint32, error) {
		return []net.IP{net.ParseIP("198.51.100.8")}, 9, nil
	}}
	slow := &traceTestServer{name: "slow", query: func(ctx context.Context, _ string, _ featureDNS.IPOption) ([]net.IP, uint32, error) {
		<-ctx.Done()
		return nil, 0, ctx.Err()
	}}
	dnsClient := newTraceTestDNS(t, []*traceTestServer{fast, slow}, nil, true)

	trace, err := dnsClient.LookupIPWithTrace(context.Background(), "parallel.example", featureDNS.IPOption{IPv4Enable: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(trace.Resolvers) != 2 || trace.Resolvers[0].Status != "winner" || trace.Resolvers[1].Status != "cancelled" ||
		trace.TTL != 9 || len(trace.Answers) != 1 || trace.Answers[0] != "198.51.100.8" {
		t.Fatalf("trace = %#v", trace)
	}
}

func TestLookupIPWithTracePreservesAttemptOnCallerTimeout(t *testing.T) {
	started := make(chan struct{})
	server := &traceTestServer{name: "blocked", query: func(ctx context.Context, _ string, _ featureDNS.IPOption) ([]net.IP, uint32, error) {
		close(started)
		<-ctx.Done()
		return nil, 0, ctx.Err()
	}}
	dnsClient := newTraceTestDNS(t, []*traceTestServer{server}, nil, false)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	trace, err := dnsClient.LookupIPWithTrace(ctx, "timeout.example", featureDNS.IPOption{IPv4Enable: true})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("resolver attempt did not start")
	}
	if err == nil || len(trace.Resolvers) != 1 || trace.Resolvers[0].Status != "timeout" || trace.Resolvers[0].LatencyMs <= 0 {
		t.Fatalf("trace=%#v err=%v", trace, err)
	}
}
