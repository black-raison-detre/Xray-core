package command

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	v2net "github.com/xtls/xray-core/common/net"
	featuredns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/tagged"
	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	defaultCapabilityTimeout = 5 * time.Second
	maxCapabilityTimeout     = 30 * time.Second
	maxCapabilityErrorLength = 240
	maxConcurrentOutbounds   = 4

	maxOutstandingCapabilityDNSLookups = maxConcurrentOutbounds * 2
)

type capabilityRuntime struct {
	dns            featuredns.Client
	dnsLookupSlots chan struct{}
	dispatcher     routing.Dispatcher
	outbounds      outbound.Manager
	dial           tagged.DialFunc
	now            func() time.Time
	random         io.Reader
	rootCAs        *x509.CertPool
}

func (s *service) TestOutboundCapabilities(ctx context.Context, request *TestOutboundCapabilitiesRequest) (*TestOutboundCapabilitiesResponse, error) {
	if s.ctx != nil {
		instanceCtx, cancel := context.WithCancel(s.ctx)
		stop := context.AfterFunc(ctx, cancel)
		defer func() {
			stop()
			cancel()
		}()
		ctx = instanceCtx
	}
	runtime, err := s.capabilityRuntime()
	if err != nil {
		return nil, err
	}
	if err := validateCapabilityRequest(request, runtime.outbounds); err != nil {
		return nil, err
	}
	if err := s.beginCapabilityCheck(request.OutboundTag); err != nil {
		return nil, err
	}
	defer s.endCapabilityCheck(request.OutboundTag)

	timeout := time.Duration(request.TimeoutMilliseconds) * time.Millisecond
	if timeout == 0 {
		timeout = defaultCapabilityTimeout
	}
	results := make([]*CapabilityProbeResult, len(request.Kinds))
	var wait sync.WaitGroup
	for index, kind := range request.Kinds {
		wait.Add(1)
		go func(index int, kind CapabilityProbeKind) {
			defer wait.Done()
			probeCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			switch kind {
			case CapabilityProbeKind_CAPABILITY_PROBE_KIND_IPV4_HTTP:
				results[index] = runHTTPFamilyProbe(probeCtx, runtime, request.OutboundTag, request.HttpUrl, true)
			case CapabilityProbeKind_CAPABILITY_PROBE_KIND_IPV6_HTTP:
				results[index] = runHTTPFamilyProbe(probeCtx, runtime, request.OutboundTag, request.HttpUrl, false)
			case CapabilityProbeKind_CAPABILITY_PROBE_KIND_UDP_DNS:
				results[index] = runUDPDNSProbe(probeCtx, runtime, request.OutboundTag, request.UdpQueryDomain, request.UdpDnsServer)
			}
		}(index, kind)
	}
	wait.Wait()
	return &TestOutboundCapabilitiesResponse{Results: results}, nil
}

func (s *service) capabilityRuntime() (capabilityRuntime, error) {
	dnsClient, _ := s.v.GetFeature(featuredns.ClientType()).(featuredns.Client)
	dispatcher, _ := s.v.GetFeature(routing.DispatcherType()).(routing.Dispatcher)
	outbounds, _ := s.v.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if dnsClient == nil || dispatcher == nil || outbounds == nil || tagged.Dialer == nil {
		return capabilityRuntime{}, status.Error(codes.Unavailable, "outbound capability checks are unavailable in this core")
	}
	return capabilityRuntime{
		dns: dnsClient, dnsLookupSlots: s.capabilityDNSLookupSlots,
		dispatcher: dispatcher, outbounds: outbounds,
		dial: tagged.Dialer, now: time.Now, random: rand.Reader,
	}, nil
}

func (s *service) beginCapabilityCheck(tag string) error {
	s.capabilityMu.Lock()
	defer s.capabilityMu.Unlock()
	if s.activeCapabilityChecks == nil {
		s.activeCapabilityChecks = make(map[string]struct{})
	}
	if _, exists := s.activeCapabilityChecks[tag]; exists {
		return status.Error(codes.AlreadyExists, "a capability check is already running for this outbound")
	}
	if len(s.activeCapabilityChecks) >= maxConcurrentOutbounds {
		return status.Error(codes.ResourceExhausted, "four outbound capability checks are already running")
	}
	s.activeCapabilityChecks[tag] = struct{}{}
	return nil
}

func (s *service) endCapabilityCheck(tag string) {
	s.capabilityMu.Lock()
	delete(s.activeCapabilityChecks, tag)
	s.capabilityMu.Unlock()
}

func validateCapabilityRequest(request *TestOutboundCapabilitiesRequest, outbounds outbound.Manager) error {
	if request == nil {
		return status.Error(codes.InvalidArgument, "request is required")
	}
	request.OutboundTag = strings.TrimSpace(request.OutboundTag)
	if request.OutboundTag == "" {
		return status.Error(codes.InvalidArgument, "outbound tag is required")
	}
	if outbounds.GetHandler(request.OutboundTag) == nil {
		return status.Error(codes.NotFound, "unknown outbound tag")
	}
	if len(request.Kinds) == 0 {
		return status.Error(codes.InvalidArgument, "select at least one capability probe")
	}
	seen := make(map[CapabilityProbeKind]struct{}, len(request.Kinds))
	for _, kind := range request.Kinds {
		switch kind {
		case CapabilityProbeKind_CAPABILITY_PROBE_KIND_IPV4_HTTP,
			CapabilityProbeKind_CAPABILITY_PROBE_KIND_IPV6_HTTP,
			CapabilityProbeKind_CAPABILITY_PROBE_KIND_UDP_DNS:
		default:
			return status.Error(codes.InvalidArgument, "unsupported capability probe kind")
		}
		if _, exists := seen[kind]; exists {
			return status.Error(codes.InvalidArgument, "duplicate capability probe kind")
		}
		seen[kind] = struct{}{}
	}
	if request.TimeoutMilliseconds > uint32(maxCapabilityTimeout/time.Millisecond) {
		return status.Error(codes.InvalidArgument, "capability timeout exceeds 30 seconds")
	}
	if _, has4 := seen[CapabilityProbeKind_CAPABILITY_PROBE_KIND_IPV4_HTTP]; has4 {
		if err := validateHTTPProbeURL(request.HttpUrl); err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
	}
	if _, has6 := seen[CapabilityProbeKind_CAPABILITY_PROBE_KIND_IPV6_HTTP]; has6 {
		if err := validateHTTPProbeURL(request.HttpUrl); err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
	}
	if _, hasUDP := seen[CapabilityProbeKind_CAPABILITY_PROBE_KIND_UDP_DNS]; hasUDP {
		if _, err := dnsQuestionName(request.UdpQueryDomain); err != nil {
			return status.Error(codes.InvalidArgument, "UDP query domain is invalid")
		}
		if _, _, err := parseDNSServer(request.UdpDnsServer); err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
	}
	return nil
}

func validateHTTPProbeURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" || parsed.User != nil ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") {
		return errors.New("HTTP probe URL must be an absolute HTTP or HTTPS URL")
	}
	if net.ParseIP(parsed.Hostname()) != nil {
		return errors.New("HTTP probe URL must use a DNS hostname")
	}
	if strings.HasSuffix(parsed.Host, ":") {
		return errors.New("HTTP probe URL port must be in range 1..65535")
	}
	if explicit := parsed.Port(); explicit != "" {
		port, convertErr := strconv.Atoi(explicit)
		if convertErr != nil || port < 1 || port > 65535 {
			return errors.New("HTTP probe URL port must be in range 1..65535")
		}
	}
	return nil
}

type dnsLookupResult struct {
	ips []v2net.IP
	err error
}

func lookupCapabilityIPs(ctx context.Context, runtime capabilityRuntime, domain string, option featuredns.IPOption) dnsLookupResult {
	if runtime.dnsLookupSlots != nil {
		select {
		case runtime.dnsLookupSlots <- struct{}{}:
		case <-ctx.Done():
			return dnsLookupResult{err: ctx.Err()}
		}
		if err := ctx.Err(); err != nil {
			<-runtime.dnsLookupSlots
			return dnsLookupResult{err: err}
		}
	}

	lookup := make(chan dnsLookupResult, 1)
	go func() {
		if runtime.dnsLookupSlots != nil {
			defer func() {
				<-runtime.dnsLookupSlots
			}()
		}
		ips, _, err := runtime.dns.LookupIP(domain, option)
		lookup <- dnsLookupResult{ips: ips, err: err}
	}()

	select {
	case <-ctx.Done():
		return dnsLookupResult{err: ctx.Err()}
	case resolved := <-lookup:
		return resolved
	}
}

func runHTTPFamilyProbe(ctx context.Context, runtime capabilityRuntime, tag, rawURL string, ipv4 bool) *CapabilityProbeResult {
	kind := CapabilityProbeKind_CAPABILITY_PROBE_KIND_IPV6_HTTP
	if ipv4 {
		kind = CapabilityProbeKind_CAPABILITY_PROBE_KIND_IPV4_HTTP
	}
	result := &CapabilityProbeResult{Kind: kind, Status: CapabilityProbeStatus_CAPABILITY_PROBE_STATUS_FAILED}
	parsed, _ := url.Parse(strings.TrimSpace(rawURL))
	resolveStarted := runtime.now()
	resolved := lookupCapabilityIPs(ctx, runtime, parsed.Hostname(), featuredns.IPOption{
		IPv4Enable: ipv4,
		IPv6Enable: !ipv4,
	})
	result.ResolutionTimeMilliseconds = runtime.now().Sub(resolveStarted).Milliseconds()
	if resolved.err != nil {
		if errors.Is(resolved.err, featuredns.ErrEmptyResponse) {
			result.Status = CapabilityProbeStatus_CAPABILITY_PROBE_STATUS_UNAVAILABLE
			result.FailureStage = "resolve"
			result.Error = "no address record for the requested family"
			return result
		}
		result.FailureStage = "resolve"
		result.Error = boundedCapabilityError(resolved.err)
		return result
	}
	familyIPs := make([]net.IP, 0, len(resolved.ips))
	for _, ip := range resolved.ips {
		standard := net.IP(ip)
		if (ipv4 && standard.To4() != nil) || (!ipv4 && standard.To4() == nil && standard.To16() != nil) {
			familyIPs = append(familyIPs, standard)
		}
	}
	if len(familyIPs) == 0 {
		result.Status = CapabilityProbeStatus_CAPABILITY_PROBE_STATUS_UNAVAILABLE
		result.FailureStage = "resolve"
		result.Error = "no address record for the requested family"
		return result
	}

	port := 80
	if parsed.Scheme == "https" {
		port = 443
	}
	if explicit := parsed.Port(); explicit != "" {
		port, _ = strconv.Atoi(explicit)
	}
	started := runtime.now()
	var lastErr error
	for _, ip := range familyIPs {
		if err := ctx.Err(); err != nil {
			lastErr = err
			break
		}
		result.Address = ip.String()
		transport := &http.Transport{
			Proxy:             nil,
			DisableKeepAlives: true,
			DialContext: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
				destination := v2net.TCPDestination(v2net.IPAddress(ip), v2net.Port(port))
				return runtime.dial(dialCtx, runtime.dispatcher, destination, tag)
			},
			TLSClientConfig:       &tls.Config{ServerName: parsed.Hostname(), RootCAs: runtime.rootCAs},
			TLSHandshakeTimeout:   time.Until(deadlineOr(ctx, runtime.now().Add(defaultCapabilityTimeout))),
			ResponseHeaderTimeout: time.Until(deadlineOr(ctx, runtime.now().Add(defaultCapabilityTimeout))),
		}
		client := &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
		if err == nil {
			var response *http.Response
			response, err = client.Do(request)
			if response != nil {
				result.HttpStatus = uint32(response.StatusCode)
				if response.Body != nil {
					_ = response.Body.Close()
				}
			}
		}
		transport.CloseIdleConnections()
		if err == nil {
			result.Status = CapabilityProbeStatus_CAPABILITY_PROBE_STATUS_REACHABLE
			result.LatencyMilliseconds = runtime.now().Sub(started).Milliseconds()
			return result
		}
		lastErr = err
	}
	result.LatencyMilliseconds = runtime.now().Sub(started).Milliseconds()
	result.FailureStage = "request"
	result.Error = boundedCapabilityError(lastErr)
	return result
}

func runUDPDNSProbe(ctx context.Context, runtime capabilityRuntime, tag, domain, server string) *CapabilityProbeResult {
	result := &CapabilityProbeResult{
		Kind: CapabilityProbeKind_CAPABILITY_PROBE_KIND_UDP_DNS, Status: CapabilityProbeStatus_CAPABILITY_PROBE_STATUS_FAILED,
	}
	ip, port, _ := parseDNSServer(server)
	name, _ := dnsQuestionName(domain)
	var idBytes [2]byte
	if _, err := io.ReadFull(runtime.random, idBytes[:]); err != nil {
		result.FailureStage = "build"
		result.Error = boundedCapabilityError(err)
		return result
	}
	id := uint16(idBytes[0])<<8 | uint16(idBytes[1])
	question := dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	query := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{question},
	}
	payload, err := query.Pack()
	if err != nil {
		result.FailureStage = "build"
		result.Error = boundedCapabilityError(err)
		return result
	}
	started := runtime.now()
	destination := v2net.UDPDestination(v2net.IPAddress(ip), v2net.Port(port))
	connection, err := runtime.dial(ctx, runtime.dispatcher, destination, tag)
	if err != nil {
		result.FailureStage = "dial"
		result.Error = boundedCapabilityError(err)
		return result
	}
	var closeOnce sync.Once
	closeConnection := func() {
		closeOnce.Do(func() {
			_ = connection.Close()
		})
	}
	stopClose := context.AfterFunc(ctx, closeConnection)
	defer func() {
		stopClose()
		closeConnection()
	}()
	result.Address = net.JoinHostPort(ip.String(), strconv.Itoa(port))
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if _, err = connection.Write(payload); err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			err = contextErr
		}
		result.FailureStage = "write"
		result.Error = boundedCapabilityError(err)
		return result
	}
	buffer := make([]byte, 64*1024)
	count, err := connection.Read(buffer)
	result.LatencyMilliseconds = runtime.now().Sub(started).Milliseconds()
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			err = contextErr
		}
		result.FailureStage = "read"
		result.Error = boundedCapabilityError(err)
		return result
	}
	var response dnsmessage.Message
	if err := response.Unpack(buffer[:count]); err != nil {
		result.FailureStage = "response"
		result.Error = boundedCapabilityError(err)
		return result
	}
	if !response.Response || response.ID != id || len(response.Questions) != 1 || response.Questions[0] != question {
		result.FailureStage = "response"
		result.Error = "DNS response did not match the transaction and question"
		return result
	}
	var answerCount uint32
	for _, answer := range response.Answers {
		if answer.Header.Type == dnsmessage.TypeA {
			answerCount++
		}
	}
	result.Status = CapabilityProbeStatus_CAPABILITY_PROBE_STATUS_REACHABLE
	result.DnsRcode = uint32(response.RCode)
	result.DnsAnswerCount = answerCount
	return result
}

func dnsQuestionName(domain string) (dnsmessage.Name, error) {
	domain = strings.TrimSpace(strings.TrimSuffix(domain, ".")) + "."
	if domain == "." {
		return dnsmessage.Name{}, errors.New("domain is required")
	}
	return dnsmessage.NewName(domain)
}

func parseDNSServer(raw string) (net.IP, int, error) {
	raw = strings.TrimSpace(raw)
	host := raw
	port := 53
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]")
	} else if parsedHost, parsedPort, err := net.SplitHostPort(raw); err == nil {
		host = parsedHost
		value, convertErr := strconv.Atoi(parsedPort)
		if convertErr != nil || value < 1 || value > 65535 {
			return nil, 0, errors.New("UDP DNS server port is invalid")
		}
		port = value
	} else if strings.HasPrefix(raw, "[") || strings.Count(raw, ":") == 1 {
		return nil, 0, errors.New("UDP DNS server must be an IP literal with an optional port")
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Equal(net.IPv4bcast) {
		return nil, 0, errors.New("UDP DNS server must be a usable unicast IP literal")
	}
	return ip, port, nil
}

func deadlineOr(ctx context.Context, fallback time.Time) time.Time {
	if deadline, ok := ctx.Deadline(); ok {
		return deadline
	}
	return fallback
}

func boundedCapabilityError(err error) string {
	if err == nil {
		return ""
	}
	text := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, err.Error())
	text = strings.TrimSpace(strings.Join(strings.Fields(text), " "))
	if len(text) > maxCapabilityErrorLength {
		return fmt.Sprintf("%s…", text[:maxCapabilityErrorLength-3])
	}
	return text
}
