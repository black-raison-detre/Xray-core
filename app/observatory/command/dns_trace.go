package command

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	featureDNS "github.com/xtls/xray-core/features/dns"
	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	maxConcurrentDNSResolveTraces = 2
	maxDNSResolveTraceDuration    = 10 * time.Second
	maxDNSResolveTraceErrorLength = 240
)

func (s *service) TraceDNSLookup(ctx context.Context, request *DNSResolveTraceRequest) (*DNSResolveTraceResponse, error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "DNS trace request is required")
	}
	queryName, questionType, option, err := validateDNSResolveTraceRequest(request)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if s.ctx != nil {
		instanceCtx, cancel := context.WithCancel(s.ctx)
		stop := context.AfterFunc(ctx, cancel)
		defer func() {
			stop()
			cancel()
		}()
		ctx = instanceCtx
	}
	ctx, timeoutCancel := context.WithTimeout(ctx, maxDNSResolveTraceDuration)
	defer timeoutCancel()
	if s.dnsTraceSlots == nil {
		return nil, status.Error(codes.Unavailable, "DNS trace is unavailable in this core")
	}
	select {
	case s.dnsTraceSlots <- struct{}{}:
		defer func() { <-s.dnsTraceSlots }()
	case <-ctx.Done():
		return nil, status.Error(codes.DeadlineExceeded, "DNS trace did not start before its deadline")
	}

	dnsClient, ok := s.v.GetFeature(featureDNS.ClientType()).(featureDNS.Client)
	if !ok || dnsClient == nil {
		return nil, status.Error(codes.Unavailable, "managed DNS feature is unavailable")
	}
	tracer, ok := dnsClient.(featureDNS.TraceClient)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "managed DNS policy tracing is not implemented by this core")
	}

	started := time.Now()
	trace, lookupErr := tracer.LookupIPWithTrace(ctx, queryName, option)
	response := &DNSResolveTraceResponse{
		QueryName:           trace.QueryName,
		QueryType:           questionType,
		ResolvedName:        trace.ResolvedName,
		Aliases:             append([]string(nil), trace.Aliases...),
		HostsStatus:         trace.HostsStatus,
		Strategy:            trace.Strategy,
		Fallback:            trace.Fallback,
		Answers:             append([]string(nil), trace.Answers...),
		Ttl:                 trace.TTL,
		LatencyMilliseconds: time.Since(started).Milliseconds(),
		Resolvers:           make([]*DNSResolveTraceResolver, 0, len(trace.Resolvers)),
		Stages:              make([]*DNSResolveTraceStage, 0, len(trace.Resolvers)+6),
	}
	if response.QueryName == "" {
		response.QueryName = queryName
	}
	if response.HostsStatus == "" {
		response.HostsStatus = "not checked"
	}
	if response.Fallback == "" {
		response.Fallback = "not reached"
	}
	if response.Strategy == "" {
		response.Strategy = "not evaluated"
	}
	for _, resolver := range trace.Resolvers {
		resolver := resolver
		response.Resolvers = append(response.Resolvers, &DNSResolveTraceResolver{
			Index: resolver.Index, Name: resolver.Name,
			MatchedRules: append([]string(nil), resolver.MatchedRules...),
			Selection:    resolver.Selection, Status: resolver.Status,
			Answers: append([]string(nil), resolver.Answers...), Error: resolver.Error,
			LatencyMilliseconds: resolver.LatencyMs,
		})
	}
	appendDNSResolveTraceStages(response, trace, lookupErr)
	return response, nil
}

func appendDNSResolveTraceStages(response *DNSResolveTraceResponse, trace featureDNS.LookupTrace, lookupErr error) {
	response.Stages = append(response.Stages, &DNSResolveTraceStage{
		Kind: "query", Label: "DNS query", Value: response.QueryName + " " + dnsTraceQueryTypeLabel(response.QueryType),
		Detail: "Ran through the active managed DNS policy. Resolver cache state is not exposed by the core.",
	})
	hostDetail := "Checked the configured static hosts map."
	if len(trace.Aliases) > 0 {
		hostDetail = "Configured domain aliases: " + strings.Join(trace.Aliases, "; ")
	}
	response.Stages = append(response.Stages, &DNSResolveTraceStage{
		Kind: "hosts", Label: "Static hosts", Value: response.HostsStatus, Detail: hostDetail,
	})
	response.Stages = append(response.Stages, &DNSResolveTraceStage{
		Kind: "strategy", Label: "Address family strategy", Value: response.Strategy,
		Detail: "The requested A or AAAA family was intersected with the running DNS feature's configured query strategy.",
	})
	response.Stages = append(response.Stages, &DNSResolveTraceStage{
		Kind: "fallback", Label: "Resolver selection", Value: response.Fallback,
		Detail: "Resolver order and fallback follow the active managed DNS policy.",
	})
	for _, resolver := range response.Resolvers {
		detail := resolver.Selection
		if len(resolver.MatchedRules) > 0 {
			detail += "; matched " + strings.Join(resolver.MatchedRules, ", ")
		}
		if resolver.Error != "" {
			detail += "; " + resolver.Error
		}
		response.Stages = append(response.Stages, &DNSResolveTraceStage{
			Kind: "resolver", Label: resolver.Name, Value: resolver.Status, Detail: detail,
		})
		if strings.EqualFold(resolver.Name, "FakeDNS") && (resolver.Status == "winner" || resolver.Status == "not selected") {
			detail := "The configured FakeDNS resolver returned a synthetic address."
			if resolver.Status == "not selected" {
				detail += " This resolver's answer was not selected by policy order."
			}
			response.Stages = append(response.Stages, &DNSResolveTraceStage{
				Kind: "answer-source", Label: "Synthetic DNS answer", Value: "FakeDNS", Detail: detail,
			})
		}
	}
	if lookupErr != nil {
		response.Error = boundedDNSResolveTraceError(lookupErr)
		response.Stages = append(response.Stages, &DNSResolveTraceStage{
			Kind: "result", Label: "DNS lookup", Value: "failed", Detail: response.Error,
		})
	} else {
		response.Stages = append(response.Stages, &DNSResolveTraceStage{
			Kind: "result", Label: "DNS answers", Value: strings.Join(response.Answers, ", "),
			Detail: fmt.Sprintf("Returned by the managed DNS feature; TTL %d seconds.", trace.TTL),
		})
	}
}

func validateDNSResolveTraceRequest(request *DNSResolveTraceRequest) (string, DNSResolveTraceQueryType, featureDNS.IPOption, error) {
	queryName := strings.TrimSuffix(strings.TrimSpace(request.GetQueryName()), ".")
	if len(queryName) == 0 || len(queryName) > 253 {
		return "", DNSResolveTraceQueryType_DNS_RESOLVE_TRACE_QUERY_TYPE_UNSPECIFIED, featureDNS.IPOption{}, errors.New("query name must contain 1 to 253 bytes")
	}
	for _, label := range strings.Split(queryName, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", 0, featureDNS.IPOption{}, errors.New("query name must contain DNS labels of 1 to 63 bytes")
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
				character >= '0' && character <= '9' || character == '-' || character == '_') {
				return "", 0, featureDNS.IPOption{}, errors.New("query name must be a DNS hostname; use punycode for international names")
			}
		}
	}
	questionName, err := dnsmessage.NewName(strings.TrimSuffix(queryName, ".") + ".")
	if err != nil {
		return "", DNSResolveTraceQueryType_DNS_RESOLVE_TRACE_QUERY_TYPE_UNSPECIFIED, featureDNS.IPOption{}, errors.New("query name is not a valid DNS name")
	}
	queryName = strings.TrimSuffix(questionName.String(), ".")
	switch request.GetQueryType() {
	case DNSResolveTraceQueryType_DNS_RESOLVE_TRACE_QUERY_TYPE_A:
		return queryName, request.GetQueryType(), featureDNS.IPOption{IPv4Enable: true, FakeEnable: true}, nil
	case DNSResolveTraceQueryType_DNS_RESOLVE_TRACE_QUERY_TYPE_AAAA:
		return queryName, request.GetQueryType(), featureDNS.IPOption{IPv6Enable: true, FakeEnable: true}, nil
	default:
		return "", DNSResolveTraceQueryType_DNS_RESOLVE_TRACE_QUERY_TYPE_UNSPECIFIED, featureDNS.IPOption{}, errors.New("query type must be A or AAAA")
	}
}

func dnsTraceQueryTypeLabel(queryType DNSResolveTraceQueryType) string {
	switch queryType {
	case DNSResolveTraceQueryType_DNS_RESOLVE_TRACE_QUERY_TYPE_A:
		return "A"
	case DNSResolveTraceQueryType_DNS_RESOLVE_TRACE_QUERY_TYPE_AAAA:
		return "AAAA"
	default:
		return "unknown"
	}
}

func boundedDNSResolveTraceError(err error) string {
	if err == nil {
		return ""
	}
	message := strings.TrimSpace(err.Error())
	if len(message) > maxDNSResolveTraceErrorLength {
		return message[:maxDNSResolveTraceErrorLength]
	}
	return message
}
