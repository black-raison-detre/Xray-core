package observatory

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	v2net "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/tagged"
)

type probeTestHandler struct {
	outbound.Handler
	tag string
}

type probeTestManager struct {
	outbound.Manager
	mu       sync.Mutex
	handlers map[string]outbound.Handler
}

func (m *probeTestManager) GetHandler(tag string) outbound.Handler {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.handlers[tag]
}

func (m *probeTestManager) setHandler(tag string, handler outbound.Handler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers[tag] = handler
}

type probeTestServer struct {
	*httptest.Server
	connections atomic.Int64
	active      atomic.Int64
	requests    atomic.Int64
}

func newProbeTestServer(t *testing.T, handler http.HandlerFunc, secure bool) *probeTestServer {
	t.Helper()
	s := &probeTestServer{}
	s.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		handler(w, r)
	}))
	s.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			s.connections.Add(1)
			s.active.Add(1)
		case http.StateClosed:
			s.active.Add(-1)
		}
	}
	if secure {
		s.StartTLS()
	} else {
		s.Start()
	}
	t.Cleanup(s.Close)
	return s
}

type probeTestContextKey struct{}

type probeTestFixture struct {
	observer *Observer
	manager  *probeTestManager
	mu       sync.Mutex
	servers  map[string]*probeTestServer
	contexts map[string]context.Context
}

func newProbeTestFixture(t *testing.T) *probeTestFixture {
	t.Helper()
	f := &probeTestFixture{
		manager:  &probeTestManager{handlers: make(map[string]outbound.Handler)},
		servers:  make(map[string]*probeTestServer),
		contexts: make(map[string]context.Context),
	}
	f.observer = &Observer{
		ctx: context.WithValue(context.Background(), probeTestContextKey{}, f),
		config: &Config{
			ProbeUrl:      "http://probe.invalid/generate_204",
			ProbeInterval: int64(time.Minute),
		},
		ohm: f.manager,
	}
	previous := tagged.Dialer
	tagged.Dialer = func(ctx context.Context, _ routing.Dispatcher, _ v2net.Destination, tag string) (net.Conn, error) {
		if ctx.Value(probeTestContextKey{}) != f {
			return nil, fmt.Errorf("dial lost the core context")
		}
		f.mu.Lock()
		server := f.servers[tag]
		f.contexts[tag] = ctx
		f.mu.Unlock()
		if server == nil {
			return nil, fmt.Errorf("no test route for tag %q", tag)
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	t.Cleanup(func() {
		_ = f.observer.Close()
		tagged.Dialer = previous
	})
	return f
}

func (f *probeTestFixture) add(t *testing.T, tag string, handler http.HandlerFunc) *probeTestServer {
	t.Helper()
	server := newProbeTestServer(t, handler, false)
	f.mu.Lock()
	f.servers[tag] = server
	f.mu.Unlock()
	f.manager.setHandler(tag, &probeTestHandler{tag: tag})
	// Close the observer before this server during cleanup, even on a failure.
	t.Cleanup(func() { _ = f.observer.Close() })
	return server
}

func waitProbeConnections(t *testing.T, server *probeTestServer, want int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for server.active.Load() != want && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := server.active.Load(); got != want {
		t.Fatalf("active connections = %d, want %d", got, want)
	}
}

func probeResponse(w http.ResponseWriter, _ *http.Request) {
	// A nonempty body also verifies draining, rather than only the 204 case.
	_, _ = w.Write([]byte("probe response"))
}

func TestObserverReusesConnectionsPerOutbound(t *testing.T) {
	f := newProbeTestFixture(t)
	const rounds = 30
	servers := map[string]*probeTestServer{}
	for _, tag := range []string{"vless", "anytls", "socks"} {
		servers[tag] = f.add(t, tag, probeResponse)
	}
	for range rounds {
		var wg sync.WaitGroup
		for tag := range servers {
			wg.Go(func() {
				if result := f.observer.probe(tag); !result.Alive {
					t.Errorf("probe %s failed: %s", tag, result.LastErrorReason)
				}
			})
		}
		wg.Wait()
	}
	for tag, server := range servers {
		if got := server.requests.Load(); got != rounds {
			t.Errorf("%s requests = %d, want %d (outbound affinity)", tag, got, rounds)
		}
		if got := server.connections.Load(); got != 1 {
			t.Errorf("%s TCP connections = %d, want 1", tag, got)
		}
		if err := f.contexts[tag].Err(); err != nil {
			t.Errorf("%s connection context canceled between probes: %v", tag, err)
		}
	}
	_ = f.observer.Close()
	for tag, server := range servers {
		waitProbeConnections(t, server, 0)
		if err := f.contexts[tag].Err(); err != context.Canceled {
			t.Errorf("%s connection context after Close = %v", tag, err)
		}
	}
}

func TestObserverInvalidatesReplacedOutbound(t *testing.T) {
	f := newProbeTestFixture(t)
	old := f.add(t, "proxy", probeResponse)
	if result := f.observer.probe("proxy"); !result.Alive {
		t.Fatal(result.LastErrorReason)
	}
	replacement := f.add(t, "proxy", probeResponse)
	for range 3 {
		if result := f.observer.probe("proxy"); !result.Alive {
			t.Fatal(result.LastErrorReason)
		}
	}
	waitProbeConnections(t, old, 0)
	if old.requests.Load() != 1 || replacement.requests.Load() != 3 || replacement.connections.Load() != 1 {
		t.Fatalf("replacement inherited stale pool: old=%d, new=%d requests/%d connections",
			old.requests.Load(), replacement.requests.Load(), replacement.connections.Load())
	}
}

func TestObserverReusesTLSConnection(t *testing.T) {
	f := newProbeTestFixture(t)
	server := newProbeTestServer(t, probeResponse, true)
	t.Cleanup(func() { _ = f.observer.Close() })
	f.servers["tls"] = server
	f.manager.setHandler("tls", &probeTestHandler{tag: "tls"})
	f.observer.config.ProbeUrl = server.URL
	client, err := f.observer.clientForOutbound("tls")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	client.transport.TLSClientConfig = &tls.Config{RootCAs: pool}
	for range 3 {
		if result := f.observer.probe("tls"); !result.Alive {
			t.Fatal(result.LastErrorReason)
		}
	}
	if server.connections.Load() != 1 || server.requests.Load() != 3 {
		t.Fatalf("TLS connection was not reused: %d connections for %d requests",
			server.connections.Load(), server.requests.Load())
	}
}

func TestObserverClosesRemovedOutboundPool(t *testing.T) {
	f := newProbeTestFixture(t)
	keep := f.add(t, "keep", probeResponse)
	drop := f.add(t, "drop", probeResponse)
	for _, tag := range []string{"keep", "drop"} {
		if result := f.observer.probe(tag); !result.Alive {
			t.Fatal(result.LastErrorReason)
		}
	}
	f.manager.setHandler("drop", nil)
	f.observer.clearRemovedOutbounds([]string{"keep"})
	waitProbeConnections(t, drop, 0)
	if result := f.observer.probe("drop"); result.Alive {
		t.Fatal("removed outbound still probed through an old connection")
	}
	if result := f.observer.probe("keep"); !result.Alive {
		t.Fatal(result.LastErrorReason)
	}
	if keep.connections.Load() != 1 || keep.requests.Load() != 2 {
		t.Fatal("pruning another outbound discarded the retained pool")
	}
}

func TestObserverRedialsClosedIdleConnection(t *testing.T) {
	f := newProbeTestFixture(t)
	server := f.add(t, "proxy", probeResponse)
	if result := f.observer.probe("proxy"); !result.Alive {
		t.Fatal(result.LastErrorReason)
	}
	server.CloseClientConnections()
	waitProbeConnections(t, server, 0)
	if result := f.observer.probe("proxy"); !result.Alive {
		t.Fatal(result.LastErrorReason)
	}
	if server.connections.Load() != 2 {
		t.Fatalf("connections = %d, want a fresh connection after peer close", server.connections.Load())
	}
}

func TestObserverCloseCancelsActiveProbe(t *testing.T) {
	f := newProbeTestFixture(t)
	started := make(chan struct{})
	server := f.add(t, "proxy", func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	})
	result := make(chan ProbeResult, 1)
	go func() { result <- f.observer.probe("proxy") }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("probe did not reach the server")
	}
	_ = f.observer.Close()
	select {
	case got := <-result:
		if got.Alive {
			t.Fatal("canceled probe reported success")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel the active probe")
	}
	waitProbeConnections(t, server, 0)
	if got := f.observer.probe("proxy"); got.Alive {
		t.Fatal("probe after Close reopened a pool")
	}
	if len(f.observer.clients) != 0 || server.connections.Load() != 1 {
		t.Fatal("Close left a cached client or allowed a new connection")
	}
	if err := f.observer.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProbeErrorCollectorConcurrentFeedback(t *testing.T) {
	collector := newErrorCollector()
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 100 {
				collector.SubmitError(fmt.Errorf("connection failed"))
				_ = collector.UnderlyingError().Error()
				collector.reset()
			}
		})
	}
	wg.Wait()
	collector.reset()
	if got := collector.UnderlyingError().Error(); got != "app/observatory: failed to produce report" {
		t.Fatalf("collector retained a previous probe's error: %s", got)
	}
}
