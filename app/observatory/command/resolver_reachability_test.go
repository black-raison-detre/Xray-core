package command

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	v2net "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/http2"
)

func resolverProbeRequest(transport ResolverProbeTransport) *TestResolverReachabilityRequest {
	return &TestResolverReachabilityRequest{
		OutboundTag: "proxy-a",
		Transport:   transport,
		Host:        "resolver.example",
		Port:        53,
		Path:        "/dns-query",
		QueryName:   "example.com",
		QueryType:   ResolverProbeQueryType_RESOLVER_PROBE_QUERY_TYPE_A,
	}
}

func resolverResponse(queryPayload []byte, rcode dnsmessage.RCode) ([]byte, error) {
	var query dnsmessage.Message
	if err := query.Unpack(queryPayload); err != nil {
		return nil, err
	}
	response := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: query.ID, Response: true, RCode: rcode},
		Questions: query.Questions,
	}
	if rcode == dnsmessage.RCodeSuccess {
		response.Answers = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name: query.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60,
			},
			Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 8}},
		}}
	}
	return response.Pack()
}

func reportResolverServerError(errors chan<- error, err error) {
	select {
	case errors <- err:
	default:
	}
}

func requireNoResolverServerError(t *testing.T, errors <-chan error) {
	t.Helper()
	select {
	case err := <-errors:
		t.Fatal(err)
	default:
	}
}

func TestResolverUDPProbeForcesOutboundAndSeparatesNegativeAnswer(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	var forcedTag string
	serverErrors := make(chan error, 1)
	go func() {
		defer server.Close()
		query := make([]byte, 4096)
		count, err := server.Read(query)
		if err != nil {
			return
		}
		response, err := resolverResponse(query[:count], dnsmessage.RCodeNameError)
		if err != nil {
			reportResolverServerError(serverErrors, err)
			return
		}
		_, _ = server.Write(response)
	}()
	result := runResolverProbe(context.Background(), capabilityRuntime{
		dial: func(_ context.Context, _ routing.Dispatcher, _ v2net.Destination, tag string) (net.Conn, error) {
			forcedTag = tag
			return client, nil
		},
		now: time.Now, random: strings.NewReader("\x12\x34"),
	}, resolverProbeRequest(ResolverProbeTransport_RESOLVER_PROBE_TRANSPORT_UDP))
	requireNoResolverServerError(t, serverErrors)
	if result.Status != ResolverProbeStatus_RESOLVER_PROBE_STATUS_REACHABLE ||
		!result.TransportReachable || !result.ProtocolValid ||
		result.DnsRcode != uint32(dnsmessage.RCodeNameError) || result.DnsAnswerCount != 0 {
		t.Fatalf("result = %#v", result)
	}
	if forcedTag != "proxy-a" {
		t.Fatalf("forced tag = %q", forcedTag)
	}
}

func TestResolverTCPProbeUsesFramingAndReturnsAnswerPreview(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	serverErrors := make(chan error, 1)
	go func() {
		defer server.Close()
		var size [2]byte
		if _, err := io.ReadFull(server, size[:]); err != nil {
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err := io.ReadFull(server, query); err != nil {
			return
		}
		response, err := resolverResponse(query, dnsmessage.RCodeSuccess)
		if err != nil {
			reportResolverServerError(serverErrors, err)
			return
		}
		framed := make([]byte, len(response)+2)
		binary.BigEndian.PutUint16(framed[:2], uint16(len(response)))
		copy(framed[2:], response)
		_, _ = server.Write(framed)
	}()
	result := runResolverProbe(context.Background(), capabilityRuntime{
		dial: func(context.Context, routing.Dispatcher, v2net.Destination, string) (net.Conn, error) {
			return client, nil
		},
		now: time.Now, random: strings.NewReader("\x12\x34"),
	}, resolverProbeRequest(ResolverProbeTransport_RESOLVER_PROBE_TRANSPORT_TCP))
	requireNoResolverServerError(t, serverErrors)
	if result.Status != ResolverProbeStatus_RESOLVER_PROBE_STATUS_REACHABLE ||
		result.DnsAnswerCount != 1 || len(result.Answers) != 1 || result.Answers[0] != "203.0.113.8" {
		t.Fatalf("result = %#v", result)
	}
}

func resolverProbeHandler(errors chan<- error) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		query, err := io.ReadAll(request.Body)
		if err != nil {
			reportResolverServerError(errors, err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		response, err := resolverResponse(query, dnsmessage.RCodeSuccess)
		if err != nil {
			reportResolverServerError(errors, err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/dns-message")
		_, _ = writer.Write(response)
	})
}

func TestResolverHTTPSProbePreservesHostAndUsesForcedDial(t *testing.T) {
	serverErrors := make(chan error, 1)
	server := httptest.NewUnstartedServer(resolverProbeHandler(serverErrors))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	port := uint32(server.Listener.Addr().(*net.TCPAddr).Port)
	request := resolverProbeRequest(ResolverProbeTransport_RESOLVER_PROBE_TRANSPORT_HTTPS)
	request.Host = "example.com"
	request.Port = port
	var forcedTag string
	result := runResolverProbe(context.Background(), capabilityRuntime{
		dial: func(_ context.Context, _ routing.Dispatcher, _ v2net.Destination, tag string) (net.Conn, error) {
			forcedTag = tag
			return net.Dial("tcp", server.Listener.Addr().String())
		},
		now:     time.Now,
		random:  strings.NewReader("\x12\x34"),
		rootCAs: server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
	}, request)
	requireNoResolverServerError(t, serverErrors)
	if result.Status != ResolverProbeStatus_RESOLVER_PROBE_STATUS_REACHABLE ||
		result.HttpStatus != http.StatusOK || result.DnsAnswerCount != 1 || forcedTag != "proxy-a" {
		t.Fatalf("result = %#v forcedTag=%q", result, forcedTag)
	}
}

func TestResolverHTTPSProbePreservesPathQuery(t *testing.T) {
	serverErrors := make(chan error, 1)
	requestTargets := make(chan string, 1)
	handler := resolverProbeHandler(serverErrors)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestTargets <- request.URL.RequestURI()
		handler.ServeHTTP(writer, request)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	request := resolverProbeRequest(ResolverProbeTransport_RESOLVER_PROBE_TRANSPORT_HTTPS)
	request.Host = "example.com"
	request.Port = uint32(server.Listener.Addr().(*net.TCPAddr).Port)
	request.Path = "/dns-query?token=x"
	result := runResolverProbe(context.Background(), capabilityRuntime{
		dial: func(context.Context, routing.Dispatcher, v2net.Destination, string) (net.Conn, error) {
			return net.Dial("tcp", server.Listener.Addr().String())
		},
		now:     time.Now,
		random:  strings.NewReader("\x12\x34"),
		rootCAs: server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
	}, request)
	requireNoResolverServerError(t, serverErrors)
	if result.Status != ResolverProbeStatus_RESOLVER_PROBE_STATUS_REACHABLE {
		t.Fatalf("result = %#v", result)
	}
	select {
	case target := <-requestTargets:
		if target != "/dns-query?token=x" {
			t.Fatalf("request target = %q", target)
		}
	default:
		t.Fatal("resolver did not receive request")
	}
}

func TestResolverH2CProbeUsesDNSWireResponse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverErrors := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		(&http2.Server{}).ServeConn(connection, &http2.ServeConnOpts{Handler: resolverProbeHandler(serverErrors)})
	}()
	request := resolverProbeRequest(ResolverProbeTransport_RESOLVER_PROBE_TRANSPORT_H2C)
	request.Port = uint32(listener.Addr().(*net.TCPAddr).Port)
	result := runResolverProbe(context.Background(), capabilityRuntime{
		dial: func(context.Context, routing.Dispatcher, v2net.Destination, string) (net.Conn, error) {
			return net.Dial("tcp", listener.Addr().String())
		},
		now: time.Now, random: strings.NewReader("\x12\x34"),
	}, request)
	requireNoResolverServerError(t, serverErrors)
	if result.Status != ResolverProbeStatus_RESOLVER_PROBE_STATUS_REACHABLE ||
		result.HttpStatus != http.StatusOK || result.DnsAnswerCount != 1 {
		t.Fatalf("result = %#v", result)
	}
}

func TestResolverHTTPSProbeRejectsNonDNSContentType(t *testing.T) {
	serverErrors := make(chan error, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		query, err := io.ReadAll(request.Body)
		if err != nil {
			reportResolverServerError(serverErrors, err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		response, err := resolverResponse(query, dnsmessage.RCodeSuccess)
		if err != nil {
			reportResolverServerError(serverErrors, err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/octet-stream")
		_, _ = writer.Write(response)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	request := resolverProbeRequest(ResolverProbeTransport_RESOLVER_PROBE_TRANSPORT_HTTPS)
	request.Host = "example.com"
	request.Port = uint32(server.Listener.Addr().(*net.TCPAddr).Port)
	result := runResolverProbe(context.Background(), capabilityRuntime{
		dial: func(context.Context, routing.Dispatcher, v2net.Destination, string) (net.Conn, error) {
			return net.Dial("tcp", server.Listener.Addr().String())
		},
		now:     time.Now,
		random:  strings.NewReader("\x12\x34"),
		rootCAs: server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
	}, request)
	requireNoResolverServerError(t, serverErrors)
	if result.Status != ResolverProbeStatus_RESOLVER_PROBE_STATUS_FAILED ||
		!result.TransportReachable || result.ProtocolValid || result.HttpStatus != http.StatusOK ||
		result.FailureStage != "http" || !strings.Contains(result.Error, "Content-Type") {
		t.Fatalf("result = %#v", result)
	}
}

func TestResolverHTTPSProbeDoesNotFollowRedirects(t *testing.T) {
	var redirected atomic.Bool
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/redirected" {
			redirected.Store(true)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		http.Redirect(writer, request, "/redirected", http.StatusFound)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	request := resolverProbeRequest(ResolverProbeTransport_RESOLVER_PROBE_TRANSPORT_HTTPS)
	request.Host = "example.com"
	request.Port = uint32(server.Listener.Addr().(*net.TCPAddr).Port)
	result := runResolverProbe(context.Background(), capabilityRuntime{
		dial: func(context.Context, routing.Dispatcher, v2net.Destination, string) (net.Conn, error) {
			return net.Dial("tcp", server.Listener.Addr().String())
		},
		now:     time.Now,
		random:  strings.NewReader("\x12\x34"),
		rootCAs: server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
	}, request)
	if result.Status != ResolverProbeStatus_RESOLVER_PROBE_STATUS_FAILED ||
		!result.TransportReachable || result.ProtocolValid || result.HttpStatus != http.StatusFound ||
		result.FailureStage != "http" || !strings.Contains(result.Error, "302") || redirected.Load() {
		t.Fatalf("result = %#v redirected=%v", result, redirected.Load())
	}
}

func TestResolverProbeRejectsMismatchedResponse(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		queryPayload := make([]byte, 4096)
		count, _ := server.Read(queryPayload)
		var query dnsmessage.Message
		_ = query.Unpack(queryPayload[:count])
		query.ID++
		query.Response = true
		response, _ := query.Pack()
		_, _ = server.Write(response)
	}()
	result := runResolverProbe(context.Background(), capabilityRuntime{
		dial: func(context.Context, routing.Dispatcher, v2net.Destination, string) (net.Conn, error) {
			return client, nil
		},
		now: time.Now, random: strings.NewReader("\x12\x34"),
	}, resolverProbeRequest(ResolverProbeTransport_RESOLVER_PROBE_TRANSPORT_UDP))
	if result.Status != ResolverProbeStatus_RESOLVER_PROBE_STATUS_FAILED ||
		!result.TransportReachable || result.ProtocolValid || result.FailureStage != "response" {
		t.Fatalf("result = %#v", result)
	}
}
