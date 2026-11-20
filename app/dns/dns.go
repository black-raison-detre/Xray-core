// Package dns is an implementation of core.DNS feature.
package dns

import (
	"context"
	go_errors "errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/features/dns"
)

// DNS is a DNS rely server.
type DNS struct {
	sync.Mutex
	disableFallback        bool
	disableFallbackIfMatch bool
	enableParallelQuery    bool
	ipOption               *dns.IPOption
	hosts                  *StaticHosts
	clients                []*Client
	ctx                    context.Context
	domainMatcher          geodata.DomainMatcher
	matcherInfos           []*DomainMatcherInfo
	checkSystem            bool
	script                 *scriptEngine
}

// DomainMatcherInfo contains information attached to index returned by Server.domainMatcher.
type DomainMatcherInfo struct {
	clientIdx  uint16
	domainRule string
}

// New creates a new DNS server with given configuration.
func New(ctx context.Context, config *Config) (*DNS, error) {
	var clientIP net.IP
	switch len(config.ClientIp) {
	case 0, net.IPv4len, net.IPv6len:
		clientIP = net.IP(config.ClientIp)
	default:
		return nil, errors.New("unexpected client IP length ", len(config.ClientIp))
	}

	var ipOption dns.IPOption
	checkSystem := false
	switch config.QueryStrategy {
	case QueryStrategy_USE_IP:
		ipOption = dns.IPOption{
			IPv4Enable: true,
			IPv6Enable: true,
			FakeEnable: false,
		}
	case QueryStrategy_USE_SYS:
		ipOption = dns.IPOption{
			IPv4Enable: true,
			IPv6Enable: true,
			FakeEnable: false,
		}
		checkSystem = true
	case QueryStrategy_USE_IP4:
		ipOption = dns.IPOption{
			IPv4Enable: true,
			IPv6Enable: false,
			FakeEnable: false,
		}
	case QueryStrategy_USE_IP6:
		ipOption = dns.IPOption{
			IPv4Enable: false,
			IPv6Enable: true,
			FakeEnable: false,
		}
	default:
		return nil, errors.New("unexpected query strategy ", config.QueryStrategy)
	}

	hosts, err := NewStaticHosts(config.StaticHosts)
	if err != nil {
		return nil, errors.New("failed to create hosts").Base(err)
	}

	defaultTag := config.Tag
	if len(config.Tag) == 0 {
		defaultTag = generateRandomTag()
	}

	clients := make([]*Client, 0, len(config.NameServer))
	matcherInfos := make([]*DomainMatcherInfo, 0)
	effectiveRules := make([]*geodata.DomainRule, 0)

	for _, ns := range config.NameServer {
		clientIdx := len(clients)
		updateRules := func(isLocalNameServer bool) {
			// Prioritize local domains with specific TLDs or those without any dot for the local DNS
			if isLocalNameServer {
				effectiveRules = append(effectiveRules, localTLDsAndDotlessDomainsRules...)
				for _, rule := range localTLDsAndDotlessDomainsRules {
					matcherInfos = append(matcherInfos, &DomainMatcherInfo{
						clientIdx:  uint16(clientIdx),
						domainRule: rule.String(),
					})
				}
			}

			effectiveRules = append(effectiveRules, ns.Domain...)
			for _, rule := range ns.Domain {
				matcherInfos = append(matcherInfos, &DomainMatcherInfo{
					clientIdx:  uint16(clientIdx),
					domainRule: rule.String(),
				})
			}
		}

		myClientIP := clientIP
		switch len(ns.ClientIp) {
		case net.IPv4len, net.IPv6len:
			myClientIP = net.IP(ns.ClientIp)
		}

		disableCache := config.DisableCache
		if ns.DisableCache != nil {
			disableCache = *ns.DisableCache
		}

		serveStale := config.ServeStale
		if ns.ServeStale != nil {
			serveStale = *ns.ServeStale
		}

		serveExpiredTTL := config.ServeExpiredTTL
		if ns.ServeExpiredTTL != nil {
			serveExpiredTTL = *ns.ServeExpiredTTL
		}

		tag := defaultTag
		if len(ns.Tag) > 0 {
			tag = ns.Tag
		}

		clientIPOption := ResolveIpOptionOverride(ns.QueryStrategy, ipOption)
		if !clientIPOption.IPv4Enable && !clientIPOption.IPv6Enable {
			return nil, errors.New("no QueryStrategy available for ", ns.Address)
		}

		client, err := NewClient(ctx, ns, myClientIP, disableCache, serveStale, serveExpiredTTL, tag, clientIPOption, updateRules)
		if err != nil {
			return nil, errors.New("failed to create client").Base(err)
		}
		clients = append(clients, client)
	}

	var domainMatcher geodata.DomainMatcher
	if len(effectiveRules) > 0 {
		domainMatcher, err = geodata.DomainReg.BuildDomainMatcher(effectiveRules)
		if err != nil {
			return nil, err
		}
	}

	// If there is no DNS client in config, add a `localhost` DNS client
	if len(clients) == 0 {
		clients = append(clients, NewLocalDNSClient(ipOption))
	}

	var script *scriptEngine
	if config.Script != "" {
		if script, err = newScriptEngine(config.Script); err != nil {
			return nil, errors.New("failed to prepare DNS script").Base(err)
		}
	}

	return &DNS{
		hosts:                  hosts,
		ipOption:               &ipOption,
		clients:                clients,
		ctx:                    ctx,
		domainMatcher:          domainMatcher,
		matcherInfos:           matcherInfos,
		disableFallback:        config.DisableFallback,
		disableFallbackIfMatch: config.DisableFallbackIfMatch,
		enableParallelQuery:    config.EnableParallelQuery,
		checkSystem:            checkSystem,
		script:                 script,
	}, nil
}

// Type implements common.HasType.
func (*DNS) Type() interface{} {
	return dns.ClientType()
}

// Start implements common.Runnable.
func (s *DNS) Start() error {
	if s.script != nil {
		if err := s.script.start(s); err != nil {
			return errors.New("failed to initialize DNS script").Base(err)
		}
	}
	return nil
}

// Close implements common.Closable.
func (s *DNS) Close() error {
	if s.script != nil {
		s.script.close()
	}
	return nil
}

// IsOwnLink implements proxy.dns.ownLinkVerifier
func (s *DNS) IsOwnLink(ctx context.Context) bool {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		return false
	}
	for _, client := range s.clients {
		if client.tag == inbound.Tag {
			return true
		}
	}
	return false
}

// MayUseSystemResolver reports whether any name server configured here could
// still resolve through the system resolver. That is what happens when no name
// server is configured at all, and it is also what a name server pointed at
// "localhost" does. Callers that are about to redirect the system resolver need
// to know, because a resolution path that reaches it would then loop back to
// them.
//
// Any such server is enough: name servers can be selected per domain, so a
// single local one makes some query reach the system resolver even when
// independent upstreams are configured alongside it.
func (s *DNS) MayUseSystemResolver() bool {
	if len(s.clients) == 0 {
		return true
	}
	for _, client := range s.clients {
		if _, isLocal := client.server.(*LocalNameServer); isLocal {
			return true
		}
	}
	return false
}

// LookupIP implements dns.Client.
func (s *DNS) LookupIP(domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	return s.lookupIP(s.ctx, domain, option, nil)
}

// LookupIPWithTrace performs a request-scoped lookup through the configured
// hosts and resolver policy and returns only decisions observed for this call.
func (s *DNS) LookupIPWithTrace(ctx context.Context, domain string, option dns.IPOption) (dns.LookupTrace, error) {
	trace := dns.LookupTrace{QueryName: strings.TrimSuffix(domain, ".")}
	ips, ttl, err := s.lookupIP(ctx, domain, option, &trace)
	trace.Answers = make([]string, 0, len(ips))
	for _, ip := range ips {
		trace.Answers = append(trace.Answers, ip.String())
	}
	trace.TTL = ttl
	return trace, err
}

func (s *DNS) lookupIP(ctx context.Context, domain string, option dns.IPOption, trace *dns.LookupTrace) ([]net.IP, uint32, error) {
	// Normalize the FQDN form query
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return nil, 0, errors.New("empty domain name")
	}
	if trace != nil {
		trace.ResolvedName = domain
	}
	requestedOption := option

	if s.checkSystem {
		supportIPv4, supportIPv6 := utils.CheckRoutes()
		option.IPv4Enable = option.IPv4Enable && supportIPv4
		option.IPv6Enable = option.IPv6Enable && supportIPv6
		if trace != nil {
			trace.Strategy = "system route availability"
		}
	} else {
		option.IPv4Enable = option.IPv4Enable && s.ipOption.IPv4Enable
		option.IPv6Enable = option.IPv6Enable && s.ipOption.IPv6Enable
		if trace != nil {
			trace.Strategy = ipOptionStrategy(s.ipOption)
		}
	}
	if trace != nil {
		trace.Strategy += "; requested " + ipOptionStrategy(&requestedOption) + "; effective " + ipOptionStrategy(&option)
	}

	if !option.IPv4Enable && !option.IPv6Enable {
		if trace != nil {
			trace.HostsStatus = "not checked"
		}
		return nil, 0, dns.ErrEmptyResponse
	}

	// Static host lookup
	var hostTrace StaticHostTrace
	switch addrs, details, err := s.hosts.LookupWithTrace(domain, option); {
	case err != nil:
		if trace != nil {
			trace.HostsStatus = "error"
		}
		if go_errors.Is(err, dns.ErrEmptyResponse) {
			return nil, 0, dns.ErrEmptyResponse
		}
		return nil, 0, errors.New("returning nil for domain ", domain).Base(err)
	case addrs == nil: // Domain not recorded in static host
		hostTrace = details
		break
	case len(addrs) == 0: // Domain recorded, but no valid IP returned (e.g. IPv4 address with only IPv6 enabled)
		hostTrace = details
		if trace != nil {
			trace.HostsStatus = hostTrace.Status
			trace.Aliases = append([]string(nil), hostTrace.Aliases...)
		}
		return nil, 0, dns.ErrEmptyResponse
	case len(addrs) == 1 && addrs[0].Family().IsDomain(): // Domain replacement
		hostTrace = details
		errors.LogInfo(s.ctx, "domain replaced: ", domain, " -> ", addrs[0].Domain())
		domain = addrs[0].Domain()
	default: // Successfully found ip records in static host
		hostTrace = details
		errors.LogInfo(s.ctx, "returning ", len(addrs), " IP(s) for domain ", domain, " -> ", addrs)
		ips, err := toNetIP(addrs)
		if err != nil {
			return nil, 0, err
		}
		if trace != nil {
			trace.HostsStatus = hostTrace.Status
			trace.Aliases = append([]string(nil), hostTrace.Aliases...)
			if hostTrace.ResolvedDomain != "" {
				trace.ResolvedName = hostTrace.ResolvedDomain
			}
		}
		return ips, 10, nil // Hosts ttl is 10
	}
	if trace != nil {
		trace.HostsStatus = hostTrace.Status
		trace.Aliases = append([]string(nil), hostTrace.Aliases...)
		if hostTrace.ResolvedDomain != "" {
			domain = hostTrace.ResolvedDomain
		}
		trace.ResolvedName = domain
	}

	// Name servers lookup
	if s.script != nil {
		if trace != nil {
			trace.Fallback = "Lua DNS policy (tracing unsupported)"
			return nil, 0, errors.New("DNS resolve tracing is unavailable for Lua DNS policies; the configured script was not executed")
		}
		return s.script.query(domain, option)
	}
	if s.enableParallelQuery {
		if trace != nil {
			return s.traceParallelQuery(ctx, domain, option, trace)
		}
		return s.parallelQuery(domain, option)
	} else {
		if trace != nil {
			return s.traceSerialQuery(ctx, domain, option, trace)
		}
		return s.serialQuery(domain, option)
	}
}

func ipOptionStrategy(option *dns.IPOption) string {
	if option == nil {
		return "unspecified"
	}
	switch {
	case option.IPv4Enable && option.IPv6Enable:
		return "IPv4 and IPv6"
	case option.IPv4Enable:
		return "IPv4 only"
	case option.IPv6Enable:
		return "IPv6 only"
	default:
		return "no address families"
	}
}

func (s *DNS) sortClients(domain string) []*Client {
	selection := s.selectClients(domain, true)
	clients := make([]*Client, 0, len(selection.entries))
	for _, entry := range selection.entries {
		clients = append(clients, entry.client)
	}
	return clients
}

type selectedDNSClient struct {
	client       *Client
	index        int
	matchedRules []string
	selection    string
}

type dnsClientSelection struct {
	entries  []selectedDNSClient
	fallback string
}

func (s *DNS) selectClients(domain string, emitLogs bool) dnsClientSelection {
	clients := make([]*Client, 0, len(s.clients))
	clientUsed := make([]bool, len(s.clients))
	clientNames := make([]string, 0, len(s.clients))
	domainRules := []string{}
	selection := dnsClientSelection{entries: make([]selectedDNSClient, 0, len(s.clients))}
	entryByClient := make(map[int]int, len(s.clients))
	addClient := func(idx int, reason string) {
		clientUsed[idx] = true
		entryByClient[idx] = len(selection.entries)
		selection.entries = append(selection.entries, selectedDNSClient{
			client: s.clients[idx], index: idx, selection: reason,
		})
		clients = append(clients, s.clients[idx])
		clientNames = append(clientNames, s.clients[idx].Name())
	}

	// Priority domain matching
	hasMatch := false
	if s.domainMatcher != nil {
		matchSlice := s.domainMatcher.Match(strings.ToLower(domain))
		sort.Slice(matchSlice, func(i, j int) bool {
			return matchSlice[i] < matchSlice[j]
		})
		for _, match := range matchSlice {
			info := s.matcherInfos[match]
			client := s.clients[info.clientIdx]
			domainRule := info.domainRule
			domainRules = append(domainRules, fmt.Sprintf("%s(DNS idx:%d)", domainRule, info.clientIdx))
			idx := int(info.clientIdx)
			if selectedIndex, exists := entryByClient[idx]; exists {
				selection.entries[selectedIndex].matchedRules = append(selection.entries[selectedIndex].matchedRules, domainRule)
			}
			if clientUsed[info.clientIdx] {
				continue
			}
			addClient(idx, "domain match")
			selection.entries[len(selection.entries)-1].matchedRules = append(selection.entries[len(selection.entries)-1].matchedRules, domainRule)
			hasMatch = true
			if client.finalQuery {
				selection.entries[len(selection.entries)-1].selection = "domain match; final query"
				if emitLogs {
					logDecision(s.ctx, domain, domainRules, clientNames)
				}
				selection.fallback = "stopped by final query"
				return selection
			}
		}
	}

	switch {
	case s.disableFallback:
		selection.fallback = "disabled by DNS policy"
	case s.disableFallbackIfMatch && hasMatch:
		selection.fallback = "disabled after domain match"
	default:
		selection.fallback = "enabled"
	}
	if selection.fallback == "enabled" {
		// Default round-robin query
		for idx, client := range s.clients {
			if clientUsed[idx] || client.skipFallback {
				continue
			}
			addClient(idx, "fallback")
			if client.finalQuery {
				selection.entries[len(selection.entries)-1].selection = "fallback; final query"
				if emitLogs {
					logDecision(s.ctx, domain, domainRules, clientNames)
				}
				selection.fallback = "stopped by final query"
				return selection
			}
		}
	}

	if emitLogs {
		logDecision(s.ctx, domain, domainRules, clientNames)
	}

	if len(selection.entries) == 0 {
		if len(s.clients) > 0 {
			addClient(0, "default resolver (no other resolver selected)")
			if selection.fallback == "enabled" {
				selection.fallback = "no eligible fallback resolver; first configured resolver used"
			} else {
				selection.fallback += "; first configured resolver used by default"
			}
			if emitLogs {
				errors.LogWarning(s.ctx, "domain ", domain, " will use the first DNS: ", clientNames)
			}
		} else {
			if emitLogs {
				errors.LogError(s.ctx, "no DNS clients available for domain ", domain, " and no default clients configured")
			}
		}
	}

	return selection
}

func logDecision(ctx context.Context, domain string, domainRules []string, clientNames []string) {
	if len(domainRules) > 0 {
		errors.LogDebug(ctx, "domain ", domain, " matches following rules: ", domainRules)
	}
	if len(clientNames) > 0 {
		errors.LogDebug(ctx, "domain ", domain, " will use DNS in order: ", clientNames)
	}
}

func mergeQueryErrors(domain string, errs []error) error {
	if len(errs) == 0 {
		return dns.ErrEmptyResponse
	}

	var noRNF error
	for _, err := range errs {
		if go_errors.Is(err, errRecordNotFound) {
			continue // server no response, ignore
		} else if noRNF == nil {
			noRNF = err
		} else if !go_errors.Is(err, noRNF) {
			return errors.New("returning nil for domain ", domain).Base(errors.Combine(errs...))
		}
	}
	if go_errors.Is(noRNF, dns.ErrEmptyResponse) {
		return dns.ErrEmptyResponse
	}
	if noRNF == nil {
		noRNF = errRecordNotFound
	}
	return errors.New("returning nil for domain ", domain).Base(noRNF)
}

func (s *DNS) traceSerialQuery(ctx context.Context, domain string, option dns.IPOption, trace *dns.LookupTrace) ([]net.IP, uint32, error) {
	selection := s.selectClients(domain, false)
	trace.Fallback = selection.fallback
	trace.Resolvers = makeResolverTrace(selection.entries)
	var errs []error
	for index, entry := range selection.entries {
		attempt := &trace.Resolvers[index]
		if !option.FakeEnable && strings.EqualFold(entry.client.Name(), "FakeDNS") {
			attempt.Status = "skipped"
			attempt.Error = "FakeDNS is disabled for this lookup"
			errs = append(errs, dns.ErrEmptyResponse)
			continue
		}
		started := time.Now()
		ips, ttl, err := entry.client.QueryIPWithTrace(ctx, domain, option)
		attempt.LatencyMs = time.Since(started).Milliseconds()
		setResolverTraceOutcome(attempt, ips, err)
		if len(ips) > 0 {
			attempt.Status = "winner"
			for pending := index + 1; pending < len(trace.Resolvers); pending++ {
				trace.Resolvers[pending].Status = "not attempted"
				trace.Resolvers[pending].Error = "a prior resolver returned an answer"
			}
			return ips, ttl, nil
		}
		if err == nil {
			err = dns.ErrEmptyResponse
		}
		errs = append(errs, err)
	}
	return nil, 0, mergeQueryErrors(domain, errs)
}

func (s *DNS) traceParallelQuery(ctx context.Context, domain string, option dns.IPOption, trace *dns.LookupTrace) ([]net.IP, uint32, error) {
	selection := s.selectClients(domain, false)
	trace.Fallback = selection.fallback
	trace.Resolvers = makeResolverTrace(selection.entries)
	if len(selection.entries) == 0 {
		return nil, 0, mergeQueryErrors(domain, nil)
	}
	clients := make([]*Client, len(selection.entries))
	for i, entry := range selection.entries {
		clients[i] = entry.client
	}

	queryCtx, cancel := context.WithCancel(ctx)
	resultsChan := make(chan queryResult, len(clients))
	for i, client := range clients {
		if !option.FakeEnable && strings.EqualFold(client.Name(), "FakeDNS") {
			resultsChan <- queryResult{err: dns.ErrEmptyResponse, index: i}
			continue
		}
		go func(i int, client *Client) {
			started := time.Now()
			ips, ttl, err := client.QueryIPWithTrace(queryCtx, domain, option)
			resultsChan <- queryResult{ips: ips, ttl: ttl, err: err, index: i, elapsed: time.Since(started)}
		}(i, client)
	}

	groups, groupOf := makeGroups(clients)
	results := make([]*queryResult, len(clients))
	pending := make([]int, len(groups))
	for gi, group := range groups {
		pending[gi] = group.end - group.start + 1
	}

	nextGroup := 0
	completed := 0
	winner := -1
	for completed < len(clients) {
		result := <-resultsChan
		completed++
		results[result.index] = &result
		traceResult := &trace.Resolvers[result.index]
		traceResult.LatencyMs = result.elapsed.Milliseconds()
		if !option.FakeEnable && strings.EqualFold(clients[result.index].Name(), "FakeDNS") {
			traceResult.Status = "skipped"
			traceResult.Error = "FakeDNS is disabled for this lookup"
		} else {
			setResolverTraceOutcome(traceResult, result.ips, result.err)
		}

		groupIndex := groupOf[result.index]
		pending[groupIndex]--
		for nextGroup < len(groups) {
			group := groups[nextGroup]
			for i := group.start; i <= group.end; i++ {
				if results[i] != nil && results[i].err == nil && len(results[i].ips) > 0 {
					winner = i
					break
				}
			}
			if winner >= 0 || pending[nextGroup] > 0 {
				break
			}
			nextGroup++
		}
		if winner >= 0 {
			markResolverWinner(trace, winner)
			break
		}
	}

	// A traced lookup owns its own context. Cancel the losing attempts as soon
	// as the winning policy group is known, then collect their terminal status
	// before returning so no goroutine can mutate request state afterwards.
	if winner >= 0 {
		cancel()
	}
	for completed < len(clients) {
		result := <-resultsChan
		completed++
		results[result.index] = &result
		traceResult := &trace.Resolvers[result.index]
		traceResult.LatencyMs = result.elapsed.Milliseconds()
		if !option.FakeEnable && strings.EqualFold(clients[result.index].Name(), "FakeDNS") {
			traceResult.Status = "skipped"
			traceResult.Error = "FakeDNS is disabled for this lookup"
		} else {
			setResolverTraceOutcome(traceResult, result.ips, result.err)
		}
		if winner >= 0 && result.index != winner && result.err == nil && len(result.ips) > 0 {
			traceResult.Status = "not selected"
			traceResult.Selection += "; answer not selected by policy order"
		}
	}
	cancel()

	if winner >= 0 {
		return results[winner].ips, results[winner].ttl, nil
	}
	errs := make([]error, 0, len(results))
	for _, result := range results {
		if result == nil {
			errs = append(errs, context.Canceled)
			continue
		}
		err := result.err
		if err == nil {
			err = dns.ErrEmptyResponse
		}
		errs = append(errs, err)
	}
	return nil, 0, mergeQueryErrors(domain, errs)
}

func markResolverWinner(trace *dns.LookupTrace, winner int) {
	for index := range trace.Resolvers {
		if index == winner {
			trace.Resolvers[index].Status = "winner"
			continue
		}
		if trace.Resolvers[index].Status == "success" {
			trace.Resolvers[index].Status = "not selected"
			trace.Resolvers[index].Selection += "; answer not selected by policy order"
		}
	}
}

func makeResolverTrace(entries []selectedDNSClient) []dns.ResolverTrace {
	trace := make([]dns.ResolverTrace, len(entries))
	for i, entry := range entries {
		trace[i] = dns.ResolverTrace{
			Index:        uint32(entry.index),
			Name:         entry.client.Name(),
			MatchedRules: append([]string(nil), entry.matchedRules...),
			Selection:    entry.selection,
			Status:       "pending",
		}
	}
	return trace
}

func setResolverTraceOutcome(trace *dns.ResolverTrace, ips []net.IP, err error) {
	trace.Answers = make([]string, 0, len(ips))
	for _, ip := range ips {
		trace.Answers = append(trace.Answers, ip.String())
	}
	switch {
	case len(ips) > 0 && err == nil:
		trace.Status = "success"
	case go_errors.Is(err, context.DeadlineExceeded):
		trace.Status = "timeout"
		trace.Error = boundedTraceError(err)
	case go_errors.Is(err, context.Canceled):
		trace.Status = "cancelled"
		trace.Error = boundedTraceError(err)
	case err == nil, go_errors.Is(err, dns.ErrEmptyResponse):
		trace.Status = "empty"
		trace.Error = "resolver returned no address for the requested family"
	default:
		trace.Status = "error"
		trace.Error = boundedTraceError(err)
	}
}

func boundedTraceError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.TrimSpace(err.Error())
	if len(value) > 240 {
		return value[:240]
	}
	return value
}

func (s *DNS) serialQuery(domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	var errs []error
	for _, client := range s.sortClients(domain) {
		if !option.FakeEnable && strings.EqualFold(client.Name(), "FakeDNS") {
			errors.LogDebug(s.ctx, "skip DNS resolution for domain ", domain, " at server ", client.Name())
			continue
		}

		ips, ttl, err := client.QueryIP(s.ctx, domain, option)

		if len(ips) > 0 {
			return ips, ttl, nil
		}

		errors.LogInfoInner(s.ctx, err, "failed to lookup ip for domain ", domain, " at server ", client.Name(), " in serial query mode")
		if err == nil {
			err = dns.ErrEmptyResponse
		}
		errs = append(errs, err)
	}
	return nil, 0, mergeQueryErrors(domain, errs)
}

func (s *DNS) parallelQuery(domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	var errs []error
	clients := s.sortClients(domain)

	resultsChan := asyncQueryAll(domain, option, clients, s.ctx)

	groups, groupOf := makeGroups( /*s.ctx,*/ clients)
	results := make([]*queryResult, len(clients))
	pending := make([]int, len(groups))
	for gi, g := range groups {
		pending[gi] = g.end - g.start + 1
	}

	nextGroup := 0
	for range clients {
		result := <-resultsChan
		results[result.index] = &result

		gi := groupOf[result.index]
		pending[gi]--

		for nextGroup < len(groups) {
			g := groups[nextGroup]

			// group race, minimum rtt -> return
			for j := g.start; j <= g.end; j++ {
				r := results[j]
				if r != nil && r.err == nil && len(r.ips) > 0 {
					return r.ips, r.ttl, nil
				}
			}

			// current group is incomplete and no one success -> continue pending
			if pending[nextGroup] > 0 {
				break
			}

			// all failed -> log and continue next group
			for j := g.start; j <= g.end; j++ {
				r := results[j]
				e := r.err
				if e == nil {
					e = dns.ErrEmptyResponse
				}
				errors.LogInfoInner(s.ctx, e, "failed to lookup ip for domain ", domain, " at server ", clients[j].Name(), " in parallel query mode")
				errs = append(errs, e)
			}
			nextGroup++
		}
	}

	return nil, 0, mergeQueryErrors(domain, errs)
}

type queryResult struct {
	ips     []net.IP
	ttl     uint32
	err     error
	index   int
	elapsed time.Duration
}

func asyncQueryAll(domain string, option dns.IPOption, clients []*Client, ctx context.Context) chan queryResult {
	if len(clients) == 0 {
		ch := make(chan queryResult)
		close(ch)
		return ch
	}

	ch := make(chan queryResult, len(clients))
	for i, client := range clients {
		if !option.FakeEnable && strings.EqualFold(client.Name(), "FakeDNS") {
			errors.LogDebug(ctx, "skip DNS resolution for domain ", domain, " at server ", client.Name())
			ch <- queryResult{err: dns.ErrEmptyResponse, index: i}
			continue
		}

		go func(i int, c *Client) {
			qctx := ctx
			if !c.server.IsDisableCache() {
				nctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.timeoutMs*2)
				qctx = nctx
				defer cancel()
			}
			ips, ttl, err := c.QueryIP(qctx, domain, option)
			ch <- queryResult{ips: ips, ttl: ttl, err: err, index: i}
		}(i, client)
	}
	return ch
}

type group struct{ start, end int }

// merge only adjacent and rule-equivalent Client into a single group
func makeGroups( /*ctx context.Context,*/ clients []*Client) ([]group, []int) {
	n := len(clients)
	if n == 0 {
		return nil, nil
	}
	groups := make([]group, 0, n)
	groupOf := make([]int, n)

	s, e := 0, 0
	for i := 1; i < n; i++ {
		if clients[i-1].policyID == clients[i].policyID {
			e = i
		} else {
			for k := s; k <= e; k++ {
				groupOf[k] = len(groups)
			}
			groups = append(groups, group{start: s, end: e})
			s, e = i, i
		}
	}
	for k := s; k <= e; k++ {
		groupOf[k] = len(groups)
	}
	groups = append(groups, group{start: s, end: e})

	// var b strings.Builder
	// b.WriteString("dns grouping: total clients=")
	// b.WriteString(strconv.Itoa(n))
	// b.WriteString(", groups=")
	// b.WriteString(strconv.Itoa(len(groups)))

	// for gi, g := range groups {
	// 	b.WriteString("\n  [")
	// 	b.WriteString(strconv.Itoa(g.start))
	// 	b.WriteString("..")
	// 	b.WriteString(strconv.Itoa(g.end))
	// 	b.WriteString("] gid=")
	// 	b.WriteString(strconv.Itoa(gi))
	// 	b.WriteString(" pid=")
	// 	b.WriteString(strconv.FormatUint(uint64(clients[g.start].policyID), 10))
	// 	b.WriteString(" members: ")

	// 	for i := g.start; i <= g.end; i++ {
	// 		if i > g.start {
	// 			b.WriteString(", ")
	// 		}
	// 		b.WriteString(strconv.Itoa(i))
	// 		b.WriteByte(':')
	// 		b.WriteString(clients[i].Name())
	// 	}
	// }
	// errors.LogDebug(ctx, b.String())

	return groups, groupOf
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}
