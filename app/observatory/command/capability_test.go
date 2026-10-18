package command

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	v2net "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/pipe"
	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type capabilityDNS struct {
	mu         sync.Mutex
	ips        []v2net.IP
	err        error
	lastDomain string
	lastOption dns.IPOption
	block      <-chan struct{}
	started    chan<- struct{}
	calls      atomic.Int32
}

func (*capabilityDNS) Type() interface{} { return dns.ClientType() }
func (*capabilityDNS) Start() error      { return nil }
func (*capabilityDNS) Close() error      { return nil }
func (d *capabilityDNS) LookupIP(domain string, option dns.IPOption) ([]v2net.IP, uint32, error) {
	d.calls.Add(1)
	d.mu.Lock()
	d.lastDomain = domain
	d.lastOption = option
	d.mu.Unlock()
	if d.started != nil {
		d.started <- struct{}{}
	}
	if d.block != nil {
		<-d.block
	}
	return d.ips, 60, d.err
}

type emptyOutboundManager struct{}

func (*emptyOutboundManager) Type() interface{}                                  { return outbound.ManagerType() }
func (*emptyOutboundManager) Start() error                                       { return nil }
func (*emptyOutboundManager) Close() error                                       { return nil }
func (*emptyOutboundManager) GetHandler(string) outbound.Handler                 { return nil }
func (*emptyOutboundManager) GetDefaultHandler() outbound.Handler                { return nil }
func (*emptyOutboundManager) AddHandler(context.Context, outbound.Handler) error { return nil }
func (*emptyOutboundManager) RemoveHandler(context.Context, string) error        { return nil }
func (*emptyOutboundManager) ListHandlers(context.Context) []outbound.Handler    { return nil }

func TestHTTPFamilyProbePreservesHostAndSNIAndAcceptsAnyStatus(t *testing.T) {
	var mu sync.Mutex
	var host, serverName, forcedTag string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		host = request.Host
		mu.Unlock()
		writer.WriteHeader(http.StatusTeapot)
	}))
	server.StartTLS()
	defer server.Close()
	server.TLS.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		mu.Lock()
		serverName = info.ServerName
		mu.Unlock()
		return nil, nil
	}
	roots := server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	resolver := &capabilityDNS{ips: []v2net.IP{net.ParseIP("127.0.0.1")}}
	runtime := capabilityRuntime{
		dns: resolver,
		dial: func(_ context.Context, _ routing.Dispatcher, _ v2net.Destination, tag string) (net.Conn, error) {
			forcedTag = tag
			return net.Dial("tcp", server.Listener.Addr().String())
		},
		now:     time.Now,
		rootCAs: roots,
	}
	result := runHTTPFamilyProbe(context.Background(), runtime, "proxy-a", "https://probe.example.com/health", true)
	if result.Status != CapabilityProbeStatus_CAPABILITY_PROBE_STATUS_REACHABLE || result.HttpStatus != http.StatusTeapot {
		t.Fatalf("result = %#v", result)
	}
	mu.Lock()
	defer mu.Unlock()
	if host != "probe.example.com" || serverName != "probe.example.com" || forcedTag != "proxy-a" {
		t.Fatalf("host=%q serverName=%q forcedTag=%q", host, serverName, forcedTag)
	}
	if resolver.lastDomain != "probe.example.com" || !resolver.lastOption.IPv4Enable || resolver.lastOption.IPv6Enable {
		t.Fatalf("lookup domain=%q option=%#v", resolver.lastDomain, resolver.lastOption)
	}
}

func TestHTTPFamilyProbeReportsMissingFamilyUnavailable(t *testing.T) {
	resolver := &capabilityDNS{err: dns.ErrEmptyResponse}
	result := runHTTPFamilyProbe(context.Background(), capabilityRuntime{
		dns: resolver,
		now: time.Now,
	}, "proxy-a", "http://probe.example/", false)
	if result.Status != CapabilityProbeStatus_CAPABILITY_PROBE_STATUS_UNAVAILABLE || result.FailureStage != "resolve" {
		t.Fatalf("result = %#v", result)
	}
	if resolver.lastOption.IPv4Enable || !resolver.lastOption.IPv6Enable {
		t.Fatalf("AAAA-only lookup option=%#v", resolver.lastOption)
	}
}

func TestHTTPFamilyProbeHonorsResolutionCancellation(t *testing.T) {
	release := make(chan struct{})
	resolver := &capabilityDNS{block: release}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	result := runHTTPFamilyProbe(ctx, capabilityRuntime{dns: resolver, now: time.Now}, "proxy-a", "http://probe.example/", true)
	close(release)
	if result.Status != CapabilityProbeStatus_CAPABILITY_PROBE_STATUS_FAILED || result.FailureStage != "resolve" ||
		!strings.Contains(result.Error, "deadline exceeded") {
		t.Fatalf("result = %#v", result)
	}
}

func TestHTTPFamilyProbeBoundsOutstandingDNSLookups(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, maxOutstandingCapabilityDNSLookups)
	resolver := &capabilityDNS{
		ips:     []v2net.IP{net.ParseIP("127.0.0.1")},
		block:   release,
		started: started,
	}
	runtime := capabilityRuntime{
		dns:            resolver,
		dnsLookupSlots: make(chan struct{}, maxOutstandingCapabilityDNSLookups),
		dial: func(context.Context, routing.Dispatcher, v2net.Destination, string) (net.Conn, error) {
			return nil, errors.New("dial stopped")
		},
		now: time.Now,
	}

	var wait sync.WaitGroup
	for range maxOutstandingCapabilityDNSLookups {
		wait.Add(1)
		go func() {
			defer wait.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
			defer cancel()
			_ = runHTTPFamilyProbe(ctx, runtime, "proxy-a", "http://probe.example/", true)
		}()
	}
	for range maxOutstandingCapabilityDNSLookups {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for DNS lookup saturation")
		}
	}
	wait.Wait()

	for range 3 {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		result := runHTTPFamilyProbe(ctx, runtime, "proxy-a", "http://probe.example/", true)
		cancel()
		if result.Status != CapabilityProbeStatus_CAPABILITY_PROBE_STATUS_FAILED ||
			result.FailureStage != "resolve" || !strings.Contains(result.Error, "deadline exceeded") {
			t.Fatalf("saturated lookup result = %#v", result)
		}
	}
	if calls := resolver.calls.Load(); calls != maxOutstandingCapabilityDNSLookups {
		t.Fatalf("blocked DNS lookups = %d, want %d", calls, maxOutstandingCapabilityDNSLookups)
	}

	close(release)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := runHTTPFamilyProbe(ctx, runtime, "proxy-a", "http://probe.example/", true)
	if result.FailureStage != "request" || !strings.Contains(result.Error, "dial stopped") {
		t.Fatalf("recovered lookup result = %#v", result)
	}
	if calls := resolver.calls.Load(); calls != maxOutstandingCapabilityDNSLookups+1 {
		t.Fatalf("DNS lookups after recovery = %d, want %d", calls, maxOutstandingCapabilityDNSLookups+1)
	}
}

func TestHTTPProbeURLPortRange(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
	}{
		{url: "http://probe.example:1/"},
		{url: "https://probe.example:65535/"},
		{url: "http://probe.example:/", wantErr: true},
		{url: "http://probe.example:0/", wantErr: true},
		{url: "http://probe.example:65536/", wantErr: true},
		{url: "http://probe.example:not-a-port/", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.url, func(t *testing.T) {
			err := validateHTTPProbeURL(test.url)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateHTTPProbeURL(%q) error = %v, wantErr %v", test.url, err, test.wantErr)
			}
		})
	}
}

func TestUDPDNSProbeTreatsNonSuccessRCodeAsReachable(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	var forcedTag string
	go func() {
		defer server.Close()
		buffer := make([]byte, 4096)
		count, err := server.Read(buffer)
		if err != nil {
			return
		}
		var query dnsmessage.Message
		if query.Unpack(buffer[:count]) != nil {
			return
		}
		response := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: query.ID, Response: true, RCode: dnsmessage.RCodeNameError},
			Questions: query.Questions,
		}
		payload, _ := response.Pack()
		_, _ = server.Write(payload)
	}()
	result := runUDPDNSProbe(context.Background(), capabilityRuntime{
		dial: func(_ context.Context, _ routing.Dispatcher, _ v2net.Destination, tag string) (net.Conn, error) {
			forcedTag = tag
			return client, nil
		},
		now: time.Now, random: strings.NewReader("\x12\x34"),
	}, "proxy-a", "google.com", "1.1.1.1:53")
	if result.Status != CapabilityProbeStatus_CAPABILITY_PROBE_STATUS_REACHABLE ||
		result.DnsRcode != uint32(dnsmessage.RCodeNameError) || result.DnsAnswerCount != 0 {
		t.Fatalf("result = %#v", result)
	}
	if forcedTag != "proxy-a" {
		t.Fatalf("forced tag = %q", forcedTag)
	}
}

func TestCapabilityDNSServerRequiresUsableUnicastLiteral(t *testing.T) {
	for _, server := range []string{"255.255.255.255:53", "224.0.0.1:53", "[ff02::1]:53"} {
		if _, _, err := parseDNSServer(server); err == nil {
			t.Fatalf("server %q was accepted", server)
		}
	}
}

func TestUDPDNSProbeRejectsMismatchedResponseAndHonorsCancellation(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		buffer := make([]byte, 4096)
		count, _ := server.Read(buffer)
		var query dnsmessage.Message
		_ = query.Unpack(buffer[:count])
		response := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID + 1, Response: true}, Questions: query.Questions}
		payload, _ := response.Pack()
		_, _ = server.Write(payload)
	}()
	result := runUDPDNSProbe(context.Background(), capabilityRuntime{
		dial: func(context.Context, routing.Dispatcher, v2net.Destination, string) (net.Conn, error) {
			return client, nil
		},
		now: time.Now, random: strings.NewReader("\x12\x34"),
	}, "proxy-a", "google.com", "1.1.1.1")
	if result.Status != CapabilityProbeStatus_CAPABILITY_PROBE_STATUS_FAILED || result.FailureStage != "response" {
		t.Fatalf("result = %#v", result)
	}

	timeoutClient, timeoutServer := net.Pipe()
	defer timeoutServer.Close()
	go func() {
		buffer := make([]byte, 4096)
		_, _ = timeoutServer.Read(buffer)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	result = runUDPDNSProbe(ctx, capabilityRuntime{
		dial: func(context.Context, routing.Dispatcher, v2net.Destination, string) (net.Conn, error) {
			return timeoutClient, nil
		},
		now: time.Now, random: strings.NewReader("\x12\x34"),
	}, "proxy-a", "google.com", "1.1.1.1")
	if result.Status != CapabilityProbeStatus_CAPABILITY_PROBE_STATUS_FAILED || result.FailureStage != "read" {
		t.Fatalf("timeout result = %#v", result)
	}
}

func TestUDPDNSProbeCancellationClosesCNCConnection(t *testing.T) {
	inputReader, inputWriter := pipe.New(pipe.WithoutSizeLimit())
	outputReader, outputWriter := pipe.New(pipe.WithoutSizeLimit())
	defer inputReader.Interrupt()
	defer outputWriter.Interrupt()

	connection := cnc.NewConnection(
		cnc.ConnectionInputMulti(inputWriter),
		cnc.ConnectionOutputMultiUDP(outputReader),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	result := runUDPDNSProbe(ctx, capabilityRuntime{
		dial: func(context.Context, routing.Dispatcher, v2net.Destination, string) (net.Conn, error) {
			return connection, nil
		},
		now: time.Now, random: strings.NewReader("\x12\x34"),
	}, "proxy-a", "google.com", "1.1.1.1")

	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("probe cancellation took %s", elapsed)
	}
	if result.Status != CapabilityProbeStatus_CAPABILITY_PROBE_STATUS_FAILED ||
		result.FailureStage != "read" || !strings.Contains(result.Error, "deadline exceeded") {
		t.Fatalf("canceled CNC result = %#v", result)
	}
}

func TestCapabilityRequestAndConcurrencyGuards(t *testing.T) {
	err := validateCapabilityRequest(&TestOutboundCapabilitiesRequest{
		OutboundTag: "missing",
		Kinds:       []CapabilityProbeKind{CapabilityProbeKind_CAPABILITY_PROBE_KIND_IPV4_HTTP},
		HttpUrl:     "https://probe.example/",
	}, &emptyOutboundManager{})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("unknown outbound error = %v", err)
	}

	service := &service{}
	for _, tag := range []string{"a", "b", "c", "d"} {
		if err := service.beginCapabilityCheck(tag); err != nil {
			t.Fatal(err)
		}
	}
	if err := service.beginCapabilityCheck("a"); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("duplicate error = %v", err)
	}
	if err := service.beginCapabilityCheck("e"); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("global bound error = %v", err)
	}
	service.endCapabilityCheck("d")
	if err := service.beginCapabilityCheck("e"); err != nil {
		t.Fatal(err)
	}
}

func TestGetOutboundStatusWithoutScheduledObservatory(t *testing.T) {
	_, err := (&service{}).GetOutboundStatus(context.Background(), &GetOutboundStatusRequest{})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("status without Observatory = %v", err)
	}
}

func TestHTTPFamilyProbeResolutionFailure(t *testing.T) {
	result := runHTTPFamilyProbe(context.Background(), capabilityRuntime{
		dns: &capabilityDNS{err: errors.New("resolver offline")}, now: time.Now,
	}, "proxy-a", "http://probe.example/", true)
	if result.Status != CapabilityProbeStatus_CAPABILITY_PROBE_STATUS_FAILED ||
		result.FailureStage != "resolve" || !strings.Contains(result.Error, "resolver offline") {
		t.Fatalf("result = %#v", result)
	}
}
