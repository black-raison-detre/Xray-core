package command

import (
	"strings"
	"testing"

	featureDNS "github.com/xtls/xray-core/features/dns"
)

func TestValidateDNSResolveTraceRequestBoundsNameAndFamily(t *testing.T) {
	for _, test := range []struct {
		name      string
		queryName string
		queryType DNSResolveTraceQueryType
		wantV4    bool
		wantV6    bool
		wantError bool
	}{
		{name: "A", queryName: "example.test", queryType: DNSResolveTraceQueryType_DNS_RESOLVE_TRACE_QUERY_TYPE_A, wantV4: true},
		{name: "AAAA", queryName: "example.test.", queryType: DNSResolveTraceQueryType_DNS_RESOLVE_TRACE_QUERY_TYPE_AAAA, wantV6: true},
		{name: "empty", queryName: "", queryType: DNSResolveTraceQueryType_DNS_RESOLVE_TRACE_QUERY_TYPE_A, wantError: true},
		{name: "invalid label", queryName: "example..test", queryType: DNSResolveTraceQueryType_DNS_RESOLVE_TRACE_QUERY_TYPE_A, wantError: true},
		{name: "oversized", queryName: strings.Repeat("a", 254), queryType: DNSResolveTraceQueryType_DNS_RESOLVE_TRACE_QUERY_TYPE_A, wantError: true},
		{name: "unsupported type", queryName: "example.test", queryType: DNSResolveTraceQueryType_DNS_RESOLVE_TRACE_QUERY_TYPE_UNSPECIFIED, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			name, _, option, err := validateDNSResolveTraceRequest(&DNSResolveTraceRequest{
				QueryName: test.queryName, QueryType: test.queryType,
			})
			if (err != nil) != test.wantError {
				t.Fatalf("validation error = %v", err)
			}
			if err == nil && (name == "" || option.IPv4Enable != test.wantV4 || option.IPv6Enable != test.wantV6 || !option.FakeEnable) {
				t.Fatalf("normalized query=%q option=%#v", name, option)
			}
		})
	}
}

func TestDNSResolveTraceStagesReportHostsDefaultsAndFakeDNSWinner(t *testing.T) {
	trace := featureDNS.LookupTrace{
		QueryName: "static.example", HostsStatus: "static", Strategy: "IPv4 only",
		Answers: []string{"192.0.2.4"}, TTL: 10,
		Resolvers: []featureDNS.ResolverTrace{{
			Name: "FakeDNS", Selection: "fallback", Status: "winner", Answers: []string{"198.18.0.2"},
		}},
	}
	response := &DNSResolveTraceResponse{
		QueryName: "static.example", QueryType: DNSResolveTraceQueryType_DNS_RESOLVE_TRACE_QUERY_TYPE_A,
		HostsStatus: "not checked", Strategy: "not evaluated", Fallback: "not reached",
		Answers: []string{"198.18.0.2"},
		Resolvers: []*DNSResolveTraceResolver{{
			Name: "FakeDNS", Selection: "fallback", Status: "winner", Answers: []string{"198.18.0.2"},
		}},
	}
	appendDNSResolveTraceStages(response, trace, nil)

	values := map[string]string{}
	fakeSource := false
	for _, stage := range response.GetStages() {
		if stage.GetKind() == "hosts" || stage.GetKind() == "fallback" {
			values[stage.GetKind()] = stage.GetValue()
		}
		if stage.GetKind() == "answer-source" && stage.GetValue() == "FakeDNS" {
			fakeSource = strings.Contains(stage.GetDetail(), "synthetic address")
		}
	}
	if values["hosts"] != "not checked" || values["fallback"] != "not reached" || !fakeSource {
		t.Fatalf("stages=%#v", response.GetStages())
	}
}
