package dns

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/net"
	featureDNS "github.com/xtls/xray-core/features/dns"
)

func TestLookupIPWithTraceDoesNotBypassLuaPolicy(t *testing.T) {
	upstream := &traceTestServer{name: "must-not-bypass-script", query: func(context.Context, string, featureDNS.IPOption) ([]net.IP, uint32, error) {
		return []net.IP{net.ParseIP("192.0.2.55")}, 60, nil
	}}
	server := newTraceTestDNS(t, []*traceTestServer{upstream}, nil, false)
	path := filepath.Join(t.TempDir(), "policy.lua")
	if err := os.WriteFile(path, []byte(`
local resolver = require("xray.dns").Servers[1]
local calls = 0
function HandleDNSQuery(domain, ipv4, ipv6, fake)
    calls = calls + 1
    local ips, _, err = resolver:Query(domain, ipv4, ipv6, fake)
    return ips, calls, err
end
`), 0o600); err != nil {
		t.Fatal(err)
	}
	engine, err := newScriptEngine(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.start(server); err != nil {
		t.Fatal(err)
	}
	defer engine.close()
	server.script = engine
	option := featureDNS.IPOption{IPv4Enable: true}
	trace, err := server.LookupIPWithTrace(context.Background(), "policy.example", option)
	if err == nil || !strings.Contains(err.Error(), "unavailable for Lua DNS policies") ||
		!strings.Contains(trace.Fallback, "Lua DNS policy") || len(trace.Resolvers) != 0 || len(trace.Answers) != 0 {
		t.Fatalf("script trace = %#v, error = %v", trace, err)
	}
	upstream.mu.Lock()
	traceQueries := upstream.queries
	upstream.mu.Unlock()
	if traceQueries != 0 {
		t.Fatalf("script policy was bypassed for %d trace queries", traceQueries)
	}
	// The trace neither ran the stateful Lua script nor fell through to the
	// standard resolver policy. Ordinary queries still follow that script.
	ips, ttl, err := server.LookupIP("policy.example", option)
	if len(ips) != 1 || ips[0].String() != "192.0.2.55" || ttl != 1 || err != nil {
		t.Fatalf("ordinary scripted lookup = %v, TTL %d, error %v", ips, ttl, err)
	}
	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	if upstream.queries != 1 {
		t.Fatalf("ordinary Lua policy made %d upstream queries, want 1", upstream.queries)
	}
}
