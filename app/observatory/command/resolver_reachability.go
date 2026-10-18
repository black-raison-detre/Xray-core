package command

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
	v2net "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/outbound"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/http2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const maxResolverProbeResponseBytes = 64 * 1024

func (s *service) TestResolverReachability(ctx context.Context, request *TestResolverReachabilityRequest) (*TestResolverReachabilityResponse, error) {
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
	if err := validateResolverProbeRequest(request, runtime.outbounds); err != nil {
		return nil, err
	}
	key := "dns:" + request.OutboundTag + ":" + request.Host + ":" + strconv.FormatUint(uint64(request.Port), 10)
	if err := s.beginCapabilityCheck(key); err != nil {
		return nil, err
	}
	defer s.endCapabilityCheck(key)

	timeout := time.Duration(request.TimeoutMilliseconds) * time.Millisecond
	if timeout == 0 {
		timeout = defaultCapabilityTimeout
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return &TestResolverReachabilityResponse{
		Result: runResolverProbe(probeCtx, runtime, request),
	}, nil
}

func validateResolverProbeRequest(request *TestResolverReachabilityRequest, outbounds outbound.Manager) error {
	if request == nil {
		return status.Error(codes.InvalidArgument, "request is required")
	}
	request.OutboundTag = strings.TrimSpace(request.OutboundTag)
	request.Host = strings.TrimSpace(strings.Trim(request.Host, "[]"))
	request.Path = strings.TrimSpace(request.Path)
	request.QueryName = strings.TrimSpace(request.QueryName)
	if request.OutboundTag == "" {
		return status.Error(codes.InvalidArgument, "outbound tag is required")
	}
	if outbounds.GetHandler(request.OutboundTag) == nil {
		return status.Error(codes.NotFound, "unknown outbound tag")
	}
	switch request.Transport {
	case ResolverProbeTransport_RESOLVER_PROBE_TRANSPORT_UDP,
		ResolverProbeTransport_RESOLVER_PROBE_TRANSPORT_TCP,
		ResolverProbeTransport_RESOLVER_PROBE_TRANSPORT_HTTPS,
		ResolverProbeTransport_RESOLVER_PROBE_TRANSPORT_H2C:
	default:
		return status.Error(codes.InvalidArgument, "unsupported resolver transport")
	}
	if request.Host == "" || strings.ContainsAny(request.Host, " \t\r\n/") {
		return status.Error(codes.InvalidArgument, "resolver host is invalid")
	}
	if ip := net.ParseIP(request.Host); ip != nil {
		if ip.IsUnspecified() || ip.IsMulticast() || ip.Equal(net.IPv4bcast) {
			return status.Error(codes.InvalidArgument, "resolver host must be a usable unicast address")
		}
	} else if _, err := dnsQuestionName(request.Host); err != nil {
		return status.Error(codes.InvalidArgument, "resolver host is invalid")
	}
	if request.Port < 1 || request.Port > 65535 {
		return status.Error(codes.InvalidArgument, "resolver port must be in range 1..65535")
	}
	if request.Transport == ResolverProbeTransport_RESOLVER_PROBE_TRANSPORT_HTTPS ||
		request.Transport == ResolverProbeTransport_RESOLVER_PROBE_TRANSPORT_H2C {
		if request.Path == "" {
			request.Path = "/dns-query"
		}
		if !strings.HasPrefix(request.Path, "/") || strings.ContainsAny(request.Path, "\r\n") {
			return status.Error(codes.InvalidArgument, "resolver request path is invalid")
		}
		if _, err := url.ParseRequestURI(request.Path); err != nil {
			return status.Error(codes.InvalidArgument, "resolver request path is invalid")
		}
	}
	if _, err := dnsQuestionName(request.QueryName); err != nil {
		return status.Error(codes.InvalidArgument, "resolver query name is invalid")
	}
	switch request.QueryType {
	case ResolverProbeQueryType_RESOLVER_PROBE_QUERY_TYPE_A,
		ResolverProbeQueryType_RESOLVER_PROBE_QUERY_TYPE_AAAA:
	default:
		return status.Error(codes.InvalidArgument, "resolver query type must be A or AAAA")
	}
	if request.TimeoutMilliseconds > uint32(maxCapabilityTimeout/time.Millisecond) {
		return status.Error(codes.InvalidArgument, "resolver timeout exceeds 30 seconds")
	}
	return nil
}

func runResolverProbe(ctx context.Context, runtime capabilityRuntime, request *TestResolverReachabilityRequest) *ResolverProbeResult {
	result := &ResolverProbeResult{Status: ResolverProbeStatus_RESOLVER_PROBE_STATUS_FAILED}
	question, payload, err := buildResolverProbeQuery(runtime, request)
	if err != nil {
		result.FailureStage = "build"
		result.Error = boundedCapabilityError(err)
		return result
	}
	started := runtime.now()
	var responsePayload []byte
	switch request.Transport {
	case ResolverProbeTransport_RESOLVER_PROBE_TRANSPORT_UDP:
		responsePayload, err = exchangeResolverPacket(ctx, runtime, request, payload, result, false)
	case ResolverProbeTransport_RESOLVER_PROBE_TRANSPORT_TCP:
		responsePayload, err = exchangeResolverPacket(ctx, runtime, request, payload, result, true)
	case ResolverProbeTransport_RESOLVER_PROBE_TRANSPORT_HTTPS,
		ResolverProbeTransport_RESOLVER_PROBE_TRANSPORT_H2C:
		responsePayload, err = exchangeResolverHTTP(ctx, runtime, request, payload, result)
	default:
		err = errors.New("unsupported resolver transport")
	}
	result.LatencyMilliseconds = runtime.now().Sub(started).Milliseconds()
	if err != nil {
		if result.FailureStage == "" {
			result.FailureStage = "request"
		}
		result.Error = boundedCapabilityError(err)
		return result
	}
	if err := acceptResolverResponse(responsePayload, payload, question, result); err != nil {
		result.FailureStage = "response"
		result.Error = boundedCapabilityError(err)
		return result
	}
	result.Status = ResolverProbeStatus_RESOLVER_PROBE_STATUS_REACHABLE
	result.ProtocolValid = true
	return result
}

func buildResolverProbeQuery(runtime capabilityRuntime, request *TestResolverReachabilityRequest) (dnsmessage.Question, []byte, error) {
	name, err := dnsQuestionName(request.QueryName)
	if err != nil {
		return dnsmessage.Question{}, nil, err
	}
	var idBytes [2]byte
	if _, err := io.ReadFull(runtime.random, idBytes[:]); err != nil {
		return dnsmessage.Question{}, nil, err
	}
	queryType := dnsmessage.TypeA
	if request.QueryType == ResolverProbeQueryType_RESOLVER_PROBE_QUERY_TYPE_AAAA {
		queryType = dnsmessage.TypeAAAA
	}
	question := dnsmessage.Question{Name: name, Type: queryType, Class: dnsmessage.ClassINET}
	query := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: uint16(idBytes[0])<<8 | uint16(idBytes[1]), RecursionDesired: true},
		Questions: []dnsmessage.Question{question},
	}
	payload, err := query.Pack()
	return question, payload, err
}

func resolverDestination(request *TestResolverReachabilityRequest, tcp bool) v2net.Destination {
	address := v2net.ParseAddress(request.Host)
	if tcp {
		return v2net.TCPDestination(address, v2net.Port(request.Port))
	}
	return v2net.UDPDestination(address, v2net.Port(request.Port))
}

func exchangeResolverPacket(
	ctx context.Context,
	runtime capabilityRuntime,
	request *TestResolverReachabilityRequest,
	payload []byte,
	result *ResolverProbeResult,
	tcp bool,
) ([]byte, error) {
	connection, err := runtime.dial(ctx, runtime.dispatcher, resolverDestination(request, tcp), request.OutboundTag)
	if err != nil {
		result.FailureStage = "dial"
		return nil, err
	}
	result.TransportReachable = true
	result.Address = net.JoinHostPort(request.Host, strconv.Itoa(int(request.Port)))
	var closeOnce sync.Once
	closeConnection := func() { closeOnce.Do(func() { _ = connection.Close() }) }
	stopClose := context.AfterFunc(ctx, closeConnection)
	defer func() {
		stopClose()
		closeConnection()
	}()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if tcp {
		framed := make([]byte, len(payload)+2)
		binary.BigEndian.PutUint16(framed[:2], uint16(len(payload)))
		copy(framed[2:], payload)
		if _, err := connection.Write(framed); err != nil {
			result.FailureStage = "write"
			return nil, resolverContextError(ctx, err)
		}
		var size [2]byte
		if _, err := io.ReadFull(connection, size[:]); err != nil {
			result.FailureStage = "read"
			return nil, resolverContextError(ctx, err)
		}
		length := int(binary.BigEndian.Uint16(size[:]))
		if length == 0 || length > maxResolverProbeResponseBytes {
			result.FailureStage = "response"
			return nil, errors.New("DNS-over-TCP response length is invalid")
		}
		response := make([]byte, length)
		if _, err := io.ReadFull(connection, response); err != nil {
			result.FailureStage = "read"
			return nil, resolverContextError(ctx, err)
		}
		return response, nil
	}
	if _, err := connection.Write(payload); err != nil {
		result.FailureStage = "write"
		return nil, resolverContextError(ctx, err)
	}
	response := make([]byte, maxResolverProbeResponseBytes)
	count, err := connection.Read(response)
	if err != nil {
		result.FailureStage = "read"
		return nil, resolverContextError(ctx, err)
	}
	return response[:count], nil
}

func exchangeResolverHTTP(
	ctx context.Context,
	runtime capabilityRuntime,
	request *TestResolverReachabilityRequest,
	payload []byte,
	result *ResolverProbeResult,
) ([]byte, error) {
	h2c := request.Transport == ResolverProbeTransport_RESOLVER_PROBE_TRANSPORT_H2C
	scheme := "https"
	if h2c {
		scheme = "http"
	}
	requestURI, err := url.ParseRequestURI(request.Path)
	if err != nil {
		result.FailureStage = "build"
		return nil, err
	}
	endpoint := url.URL{
		Scheme:     scheme,
		Host:       net.JoinHostPort(request.Host, strconv.Itoa(int(request.Port))),
		Path:       requestURI.Path,
		RawPath:    requestURI.RawPath,
		ForceQuery: requestURI.ForceQuery,
		RawQuery:   requestURI.RawQuery,
	}
	var dialed atomic.Bool
	transport := &http2.Transport{
		AllowHTTP: h2c,
		DialTLSContext: func(dialCtx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
			connection, err := runtime.dial(dialCtx, runtime.dispatcher, resolverDestination(request, true), request.OutboundTag)
			if err != nil {
				return nil, err
			}
			dialed.Store(true)
			if h2c {
				return connection, nil
			}
			tlsConnection := utls.UClient(connection, &utls.Config{
				ServerName: request.Host,
				RootCAs:    runtime.rootCAs,
			}, utls.HelloChrome_Auto)
			if err := tlsConnection.HandshakeContext(dialCtx); err != nil {
				_ = connection.Close()
				return nil, err
			}
			return tlsConnection, nil
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		result.FailureStage = "build"
		return nil, err
	}
	httpRequest.Header.Set("Accept", "application/dns-message")
	httpRequest.Header.Set("Content-Type", "application/dns-message")
	response, err := client.Do(httpRequest)
	result.TransportReachable = dialed.Load()
	result.Address = endpoint.Host
	if err != nil {
		result.FailureStage = "request"
		return nil, resolverContextError(ctx, err)
	}
	defer response.Body.Close()
	result.HttpStatus = uint32(response.StatusCode)
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResolverProbeResponseBytes))
		result.FailureStage = "http"
		return nil, fmt.Errorf("DoH server returned HTTP %d", response.StatusCode)
	}
	mediaType, _, mediaTypeErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaTypeErr != nil || !strings.EqualFold(mediaType, "application/dns-message") {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResolverProbeResponseBytes))
		result.FailureStage = "http"
		return nil, fmt.Errorf("DoH server returned Content-Type %q instead of application/dns-message", response.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResolverProbeResponseBytes+1))
	if err != nil {
		result.FailureStage = "read"
		return nil, err
	}
	if len(body) == 0 || len(body) > maxResolverProbeResponseBytes {
		result.FailureStage = "response"
		return nil, errors.New("DoH response length is invalid")
	}
	return body, nil
}

func acceptResolverResponse(payload, queryPayload []byte, question dnsmessage.Question, result *ResolverProbeResult) error {
	var response dnsmessage.Message
	if err := response.Unpack(payload); err != nil {
		return err
	}
	var query dnsmessage.Message
	if err := query.Unpack(queryPayload); err != nil {
		return err
	}
	if !response.Response || response.ID != query.ID || len(response.Questions) != 1 || response.Questions[0] != question {
		return errors.New("DNS response did not match the transaction and question")
	}
	result.DnsRcode = uint32(response.RCode)
	result.DnsAnswerCount = uint32(len(response.Answers))
	result.Truncated = response.Truncated
	result.Answers = resolverAnswerPreview(response.Answers)
	return nil
}

func resolverAnswerPreview(resources []dnsmessage.Resource) []string {
	answers := make([]string, 0, 6)
	for _, resource := range resources {
		if len(answers) == cap(answers) {
			break
		}
		switch body := resource.Body.(type) {
		case *dnsmessage.AResource:
			answers = append(answers, net.IP(body.A[:]).String())
		case *dnsmessage.AAAAResource:
			answers = append(answers, net.IP(body.AAAA[:]).String())
		case *dnsmessage.CNAMEResource:
			answers = append(answers, body.CNAME.String())
		}
	}
	return answers
}

func resolverContextError(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	return err
}
