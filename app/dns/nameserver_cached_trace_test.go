package dns

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	featureDNS "github.com/xtls/xray-core/features/dns"
)

// Exercise the actual shared cache, pubsub and singleflight pipeline rather
// than replacing the traced DNS policy's clients with an immediate stub.
type traceIsolationCachedServer struct {
	cache   *CacheController
	started chan context.Context
	reply   chan struct{}
}

func (s *traceIsolationCachedServer) Name() string                         { return "cached-test" }
func (s *traceIsolationCachedServer) IsDisableCache() bool                 { return false }
func (s *traceIsolationCachedServer) getCacheController() *CacheController { return s.cache }
func (s *traceIsolationCachedServer) QueryIP(ctx context.Context, domain string, option featureDNS.IPOption) ([]net.IP, uint32, error) {
	return queryIP(ctx, s, domain, option)
}

func (s *traceIsolationCachedServer) sendQuery(ctx context.Context, failure chan<- error, fqdn string, _ featureDNS.IPOption) {
	s.started <- ctx
	go func() {
		select {
		case <-ctx.Done():
			failure <- ctx.Err()
		case <-s.reply:
			s.cache.pub.Publish(fqdn+"4", &IPRecord{IP: []net.IP{net.ParseIP("192.0.2.33")}, Expire: time.Now().Add(time.Minute)})
		}
	}()
}

func TestCachedNameserverTraceCancellationIsIndependentOfNormalLookup(t *testing.T) {
	for _, traceFirst := range []bool{true, false} {
		name := "normal-leads"
		if traceFirst {
			name = "trace-leads"
		}
		t.Run(name, func(t *testing.T) {
			server := &traceIsolationCachedServer{
				cache:   NewCacheController("cached-test", false, false, 0),
				started: make(chan context.Context, 4), reply: make(chan struct{}),
			}
			client := &Client{server: server, timeoutMs: 2 * time.Second, ipOption: &featureDNS.IPOption{IPv4Enable: true}}
			normalCtx, normalCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer normalCancel()
			traceCtx, traceCancel := context.WithCancel(context.Background())
			defer traceCancel()
			normalDone, traceDone := make(chan result, 1), make(chan result, 1)
			startNormal := func() {
				go func() {
					ips, ttl, err := client.QueryIP(normalCtx, "same.example", featureDNS.IPOption{IPv4Enable: true})
					normalDone <- result{ips, ttl, err}
				}()
			}
			startTrace := func() {
				go func() {
					ips, ttl, err := client.QueryIPWithTrace(traceCtx, "same.example", featureDNS.IPOption{IPv4Enable: true})
					traceDone <- result{ips, ttl, err}
				}()
			}
			waitStarted := func() {
				t.Helper()
				select {
				case <-server.started:
				case <-time.After(time.Second):
					t.Fatal("trace joined an ordinary singleflight request instead of independent work")
				}
			}
			if traceFirst {
				startTrace()
			} else {
				startNormal()
			}
			waitStarted()
			if traceFirst {
				startNormal()
			} else {
				startTrace()
			}
			waitStarted()
			traceCancel()
			select {
			case response := <-traceDone:
				if !errors.Is(response.error, context.Canceled) {
					t.Fatalf("trace cancellation = %v", response.error)
				}
			case <-time.After(time.Second):
				t.Fatal("cancelled trace waited for the ordinary resolver")
			}
			select {
			case response := <-normalDone:
				t.Fatalf("trace cancellation completed ordinary lookup: %#v", response)
			default:
			}
			close(server.reply)
			select {
			case response := <-normalDone:
				if response.error != nil || len(response.ips) != 1 || response.ips[0].String() != "192.0.2.33" {
					t.Fatalf("ordinary lookup result = %#v", response)
				}
			case <-time.After(time.Second):
				t.Fatal("ordinary query failed to receive its own response")
			}
		})
	}
}
