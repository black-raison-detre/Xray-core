package dns

import (
	"context"
	go_errors "errors"
	"fmt"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/egress"
	"github.com/xtls/xray-core/features/routing"
)

type egressResolverFactory func(net.Destination) Server

var errEgressGenerationChanged = go_errors.New("TUN egress generation changed during DNS lookup")

const (
	maxEgressResolverAttempt = 2 * time.Second
	maxEgressLookupDuration  = 4 * time.Second
)

// SystemEgressNameServer resolves through numeric DNS servers belonging to
// the active TUN egress selection. Each generation gets fresh classic DNS
// clients, so a prior network's cached answers cannot survive reselection.
type SystemEgressNameServer struct {
	dispatcher   routing.Dispatcher
	disableCache bool
	serveStale   bool
	serveExpired uint32
	port         net.Port
	clientIP     net.IP
	snapshot     func(context.Context) *egress.Snapshot
	newResolver  egressResolverFactory
	mu           sync.Mutex
	generation   uint64
	resolvers    map[string]Server
}

func NewSystemEgressNameServer(dispatcher routing.Dispatcher, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP net.IP, port net.Port) *SystemEgressNameServer {
	s := &SystemEgressNameServer{
		dispatcher:   dispatcher,
		disableCache: disableCache,
		serveStale:   serveStale,
		serveExpired: serveExpiredTTL,
		port:         port,
		clientIP:     append(net.IP(nil), clientIP...),
		snapshot: func(ctx context.Context) *egress.Snapshot {
			return egress.Status(ctx, egress.Request{})
		},
	}
	s.newResolver = func(destination net.Destination) Server {
		return NewClassicNameServer(destination, s.dispatcher, s.disableCache, s.serveStale, s.serveExpired, s.clientIP)
	}
	return s
}

func (s *SystemEgressNameServer) Name() string { return egress.SystemEgressDNSAddress }

func (s *SystemEgressNameServer) IsDisableCache() bool { return s.disableCache }

func (s *SystemEgressNameServer) QueryIP(ctx context.Context, domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	for attempt := 0; attempt < 2; attempt++ {
		snapshot := s.snapshot(ctx)
		if snapshot == nil || snapshot.State != "active" {
			return nil, 0, fmt.Errorf("%s requires an active TUN egress selection", egress.SystemEgressDNSAddress)
		}
		ips, ttl, queryErr := s.querySnapshot(ctx, snapshot, domain, option)
		current := s.snapshot(ctx)
		if current != nil && current.State == "active" && current.Generation == snapshot.Generation {
			return ips, ttl, queryErr
		}
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
	}
	return nil, 0, fmt.Errorf("TUN egress selection changed during %s lookup", egress.SystemEgressDNSAddress)
}

func (s *SystemEgressNameServer) querySnapshot(ctx context.Context, snapshot *egress.Snapshot, domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	type resolverTarget struct {
		family  string
		luid    string
		address string
	}
	targets := make([]resolverTarget, 0, 4)
	for _, family := range []string{"ipv4", "ipv6"} {
		luid, addresses := egress.DNSForFamily(snapshot, family)
		for _, address := range addresses {
			targets = append(targets, resolverTarget{family: family, luid: luid, address: address})
		}
	}
	if len(targets) == 0 {
		return nil, 0, fmt.Errorf("no usable DNS server is selected by active TUN egress")
	}
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		deadline = time.Now().Add(maxEgressLookupDuration)
	}
	var queryErrors []error
	for index, target := range targets {
		current := s.snapshot(ctx)
		if current == nil || current.State != "active" || current.Generation != snapshot.Generation {
			return nil, 0, errEgressGenerationChanged
		}
		resolver, err := s.resolverFor(snapshot.Generation, target.family, target.luid, target.address)
		if err != nil {
			queryErrors = append(queryErrors, err)
			continue
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, 0, context.DeadlineExceeded
		}
		attemptTimeout := remaining / time.Duration(len(targets)-index+1)
		if attemptTimeout > maxEgressResolverAttempt {
			attemptTimeout = maxEgressResolverAttempt
		}
		attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
		ips, ttl, queryErr := resolver.QueryIP(attemptCtx, domain, option)
		cancel()
		if queryErr == nil && len(ips) > 0 {
			return ips, ttl, nil
		}
		if queryErr == nil {
			queryErr = dns.ErrEmptyResponse
		}
		queryErrors = append(queryErrors, queryErr)
		if ctx.Err() != nil {
			return nil, 0, ctx.Err()
		}
		current = s.snapshot(ctx)
		if current == nil || current.State != "active" || current.Generation != snapshot.Generation {
			return nil, 0, errEgressGenerationChanged
		}
	}
	return nil, 0, errors.Combine(queryErrors...)
}

func (s *SystemEgressNameServer) resolverFor(generation uint64, family, luid, address string) (Server, error) {
	parsed := net.ParseAddress(address)
	if parsed == nil || !parsed.Family().IsIP() {
		return nil, fmt.Errorf("selected %s DNS server %q is not numeric", family, address)
	}
	if family == "ipv4" && !parsed.Family().IsIPv4() || family == "ipv6" && !parsed.Family().IsIPv6() {
		return nil, fmt.Errorf("selected %s DNS server %q has the wrong address family", family, address)
	}
	key := family + "/" + luid + "/" + address
	s.mu.Lock()
	defer s.mu.Unlock()
	if generation < s.generation {
		return nil, errEgressGenerationChanged
	}
	if generation != s.generation {
		for _, resolver := range s.resolvers {
			if closer, ok := resolver.(interface{ Close() error }); ok {
				_ = closer.Close()
			}
		}
		s.generation = generation
		s.resolvers = make(map[string]Server)
	}
	if resolver := s.resolvers[key]; resolver != nil {
		return resolver, nil
	}
	destination := net.Destination{Network: net.Network_UDP, Address: parsed, Port: s.port}
	resolver := s.newResolver(destination)
	s.resolvers[key] = resolver
	return resolver, nil
}
