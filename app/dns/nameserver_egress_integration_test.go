package dns

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	miekgdns "github.com/miekg/dns"
	"github.com/xtls/xray-core/common/buf"
	coreNet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features"
	dnsfeature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/egress"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type egressDNSRequest struct {
	destination coreNet.Destination
	name        string
	qtype       uint16
}

type egressDNSDispatch func(coreNet.Destination, *miekgdns.Msg) (*miekgdns.Msg, <-chan struct{})

// egressDNSDispatcher carries packed DNS messages over in-memory Xray pipes.
// It exercises ClassicNameServer's production dispatcher and wire parser
// without opening a socket or consulting the host resolver.
type egressDNSDispatcher struct {
	mu       sync.Mutex
	links    []*egressDNSPipeLink
	requests chan egressDNSRequest
	respond  egressDNSDispatch
}

type egressDNSPipeLink struct {
	request  *pipe.Writer
	response *pipe.Writer
}

var (
	_ routing.Dispatcher = (*egressDNSDispatcher)(nil)
	_ features.Feature   = (*egressDNSDispatcher)(nil)
)

func (d *egressDNSDispatcher) Type() interface{} { return routing.DispatcherType() }
func (d *egressDNSDispatcher) Start() error      { return nil }
func (d *egressDNSDispatcher) Close() error      { return nil }

func (d *egressDNSDispatcher) close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, link := range d.links {
		_ = link.request.Close()
		_ = link.response.Close()
	}
}

func (d *egressDNSDispatcher) Dispatch(ctx context.Context, destination coreNet.Destination) (*transport.Link, error) {
	requestReader, requestWriter := pipe.New(pipe.WithoutSizeLimit())
	responseReader, responseWriter := pipe.New(pipe.WithoutSizeLimit())
	d.mu.Lock()
	d.links = append(d.links, &egressDNSPipeLink{request: requestWriter, response: responseWriter})
	d.mu.Unlock()
	go func() {
		<-ctx.Done()
		_ = requestWriter.Close()
		_ = responseWriter.Close()
	}()
	go func() {
		defer responseWriter.Close()
		for {
			multi, err := requestReader.ReadMultiBuffer()
			if err != nil {
				return
			}
			for _, packet := range multi {
				query := new(miekgdns.Msg)
				unpackErr := query.Unpack(packet.Bytes())
				packet.Release()
				if unpackErr != nil || len(query.Question) == 0 {
					continue
				}
				question := query.Question[0]
				select {
				case d.requests <- egressDNSRequest{destination: destination, name: question.Name, qtype: question.Qtype}:
				case <-ctx.Done():
					return
				}
				response, wait := d.respond(destination, query)
				if response == nil {
					continue
				}
				if wait != nil {
					select {
					case <-wait:
					case <-ctx.Done():
						return
					}
				}
				wire, err := response.Pack()
				if err != nil {
					continue
				}
				if err := responseWriter.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(wire)}); err != nil {
					return
				}
			}
		}
	}()
	return &transport.Link{Reader: responseReader, Writer: requestWriter}, nil
}

func (d *egressDNSDispatcher) DispatchLink(context.Context, coreNet.Destination, *transport.Link) error {
	return fmt.Errorf("DispatchLink is not used by the DNS protocol fixture")
}

func newEgressTestSnapshot(generation uint64, ipv4DNS, ipv6DNS []string) *egress.Snapshot {
	snapshot := &egress.Snapshot{State: "active", Generation: generation}
	if ipv4DNS != nil {
		snapshot.IPv4 = egress.FamilyStatus{State: "selected", Interface: &egress.Interface{Name: "adapter-v4", LUID: "v4-luid", DNSServers: ipv4DNS}}
	}
	if ipv6DNS != nil {
		snapshot.IPv6 = egress.FamilyStatus{State: "selected", Interface: &egress.Interface{Name: "adapter-v6", LUID: "v6-luid", DNSServers: ipv6DNS}}
	}
	return snapshot
}

func makeEgressDNSAnswer(query *miekgdns.Msg, address string) *miekgdns.Msg {
	response := new(miekgdns.Msg)
	response.SetReply(query)
	question := query.Question[0]
	var record string
	switch question.Qtype {
	case miekgdns.TypeA:
		record = fmt.Sprintf("%s 30 IN A %s", question.Name, address)
	case miekgdns.TypeAAAA:
		record = fmt.Sprintf("%s 30 IN AAAA %s", question.Name, address)
	default:
		return response
	}
	rr, err := miekgdns.NewRR(record)
	if err != nil {
		return response
	}
	response.Answer = []miekgdns.RR{rr}
	return response
}

func newTestSystemEgressNameServer(snapshot func(context.Context) *egress.Snapshot, dispatcher routing.Dispatcher) *SystemEgressNameServer {
	server := NewSystemEgressNameServer(dispatcher, false, false, 0, nil, coreNet.Port(1053))
	server.snapshot = snapshot
	return server
}

func withSystemEgressCoreContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, core.XrayKey(1), &core.Instance{})
}

func awaitEgressDNSRequest(t *testing.T, requests <-chan egressDNSRequest) egressDNSRequest {
	return awaitEgressDNSRequestWithin(t, requests, 2*time.Second)
}

func awaitEgressDNSRequestWithin(t *testing.T, requests <-chan egressDNSRequest, timeout time.Duration) egressDNSRequest {
	t.Helper()
	select {
	case request := <-requests:
		return request
	case <-time.After(timeout):
		t.Fatal("timed out waiting for DNS wire request")
		return egressDNSRequest{}
	}
}

func TestSystemEgressNameServerRebuildsClassicResolverOnNetworkGeneration(t *testing.T) {
	var snapshotMu sync.RWMutex
	snapshot := newEgressTestSnapshot(1, []string{"1.1.1.1"}, nil)
	getSnapshot := func(context.Context) *egress.Snapshot {
		snapshotMu.RLock()
		defer snapshotMu.RUnlock()
		return snapshot
	}
	dispatcher := &egressDNSDispatcher{
		requests: make(chan egressDNSRequest, 8),
		respond: func(destination coreNet.Destination, query *miekgdns.Msg) (*miekgdns.Msg, <-chan struct{}) {
			answer := "198.51.100.1"
			if destination.Address.IP().String() == "9.9.9.9" {
				answer = "198.51.100.2"
			}
			return makeEgressDNSAnswer(query, answer), nil
		},
	}
	server := newTestSystemEgressNameServer(getSnapshot, dispatcher)
	t.Cleanup(dispatcher.close)
	lookup := func() net.IP {
		t.Helper()
		ctx, cancel := context.WithTimeout(withSystemEgressCoreContext(context.Background()), 2*time.Second)
		defer cancel()
		ips, _, err := server.QueryIP(ctx, "rotate.example", dnsfeature.IPOption{IPv4Enable: true})
		if err != nil {
			t.Fatalf("QueryIP failed: %v", err)
		}
		if len(ips) != 1 {
			t.Fatalf("QueryIP returned %d addresses, want 1", len(ips))
		}
		return ips[0]
	}

	if got := lookup().String(); got != "198.51.100.1" {
		t.Fatalf("initial answer = %s, want old adapter answer", got)
	}
	first := awaitEgressDNSRequest(t, dispatcher.requests)
	if first.destination.Address.IP().String() != "1.1.1.1" || first.destination.Port != 1053 {
		t.Fatalf("initial resolver destination = %s, want 1.1.1.1:1053", first.destination)
	}
	// A same-generation lookup must hit the ClassicNameServer cache.
	if got := lookup().String(); got != "198.51.100.1" {
		t.Fatalf("cached answer = %s, want 198.51.100.1", got)
	}
	select {
	case request := <-dispatcher.requests:
		t.Fatalf("same-generation lookup unexpectedly queried DNS again: %+v", request)
	default:
	}

	snapshotMu.Lock()
	snapshot = newEgressTestSnapshot(2, []string{"9.9.9.9"}, nil)
	snapshotMu.Unlock()
	if got := lookup().String(); got != "198.51.100.2" {
		t.Fatalf("answer after network generation changed = %s, want 198.51.100.2", got)
	}
	second := awaitEgressDNSRequest(t, dispatcher.requests)
	if second.destination.Address.IP().String() != "9.9.9.9" || second.destination.Port != 1053 {
		t.Fatalf("replacement resolver destination = %s, want 9.9.9.9:1053", second.destination)
	}
}

func TestSystemEgressNameServerRejectsOldInFlightGenerationAnswer(t *testing.T) {
	var snapshotMu sync.RWMutex
	snapshot := newEgressTestSnapshot(10, []string{"1.1.1.1"}, nil)
	getSnapshot := func(context.Context) *egress.Snapshot {
		snapshotMu.RLock()
		defer snapshotMu.RUnlock()
		return snapshot
	}
	oldRequestStarted := make(chan struct{})
	releaseOldResponse := make(chan struct{})
	var oldOnce sync.Once
	dispatcher := &egressDNSDispatcher{
		requests: make(chan egressDNSRequest, 8),
		respond: func(destination coreNet.Destination, query *miekgdns.Msg) (*miekgdns.Msg, <-chan struct{}) {
			if destination.Address.IP().String() == "1.1.1.1" {
				oldOnce.Do(func() { close(oldRequestStarted) })
				return makeEgressDNSAnswer(query, "198.51.100.10"), releaseOldResponse
			}
			return makeEgressDNSAnswer(query, "198.51.100.20"), nil
		},
	}
	server := newTestSystemEgressNameServer(getSnapshot, dispatcher)
	t.Cleanup(dispatcher.close)
	type lookupResult struct {
		ips []net.IP
		err error
	}
	result := make(chan lookupResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(withSystemEgressCoreContext(context.Background()), 3*time.Second)
		defer cancel()
		ips, _, err := server.QueryIP(ctx, "moving.example", dnsfeature.IPOption{IPv4Enable: true})
		result <- lookupResult{ips: ips, err: err}
	}()
	awaitEgressDNSRequest(t, dispatcher.requests)
	select {
	case <-oldRequestStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("old-generation DNS request did not reach the protocol fixture")
	}

	snapshotMu.Lock()
	snapshot = newEgressTestSnapshot(11, []string{"9.9.9.9"}, nil)
	snapshotMu.Unlock()
	close(releaseOldResponse)

	select {
	case got := <-result:
		if got.err != nil {
			t.Fatalf("QueryIP failed after generation changed: %v", got.err)
		}
		if len(got.ips) != 1 || got.ips[0].String() != "198.51.100.20" {
			t.Fatalf("in-flight lookup returned %v, want replacement-generation answer 198.51.100.20", got.ips)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("QueryIP did not finish after releasing old response")
	}
	newRequest := awaitEgressDNSRequest(t, dispatcher.requests)
	if newRequest.destination.Address.IP().String() != "9.9.9.9" {
		t.Fatalf("retry used %s, want new adapter DNS 9.9.9.9", newRequest.destination.Address)
	}
}

func TestSystemEgressNameServerDoesNotUseStaleDNSWhenSelectionIsUnavailable(t *testing.T) {
	var current *egress.Snapshot = newTestSystemSnapshotForOutage()
	var snapshotMu sync.RWMutex
	dispatcher := &egressDNSDispatcher{
		requests: make(chan egressDNSRequest, 4),
		respond: func(destination coreNet.Destination, query *miekgdns.Msg) (*miekgdns.Msg, <-chan struct{}) {
			return makeEgressDNSAnswer(query, "198.51.100.30"), nil
		},
	}
	server := newTestSystemEgressNameServer(func(context.Context) *egress.Snapshot {
		snapshotMu.RLock()
		defer snapshotMu.RUnlock()
		return current
	}, dispatcher)
	t.Cleanup(dispatcher.close)
	ctx, cancel := context.WithTimeout(withSystemEgressCoreContext(context.Background()), 2*time.Second)
	defer cancel()
	ips, _, err := server.QueryIP(ctx, "outage.example", dnsfeature.IPOption{IPv4Enable: true})
	if err != nil || len(ips) != 1 || ips[0].String() != "198.51.100.30" {
		t.Fatalf("initial lookup = %v, %v; want fixture answer", ips, err)
	}
	awaitEgressDNSRequest(t, dispatcher.requests)

	snapshotMu.Lock()
	current = &egress.Snapshot{State: "inactive", Generation: 2}
	snapshotMu.Unlock()
	ips, _, err = server.QueryIP(ctx, "outage.example", dnsfeature.IPOption{IPv4Enable: true})
	if err == nil || len(ips) != 0 {
		t.Fatalf("lookup without active adapter returned %v, %v; want an error and no stale answer", ips, err)
	}
	select {
	case request := <-dispatcher.requests:
		t.Fatalf("outage lookup unexpectedly used old resolver %s", request.destination)
	default:
	}
}

func newTestSystemSnapshotForOutage() *egress.Snapshot {
	return newEgressTestSnapshot(1, []string{"1.1.1.1"}, nil)
}

func TestSystemEgressNameServerQueryFamilyIsIndependentOfDNSTransportFamily(t *testing.T) {
	tests := []struct {
		name        string
		ipv4DNS     []string
		ipv6DNS     []string
		option      dnsfeature.IPOption
		wantAddress string
		wantServer  string
	}{
		{name: "AAAA over IPv4 DNS", ipv4DNS: []string{"1.1.1.1"}, option: dnsfeature.IPOption{IPv6Enable: true}, wantAddress: "2001:db8::1", wantServer: "1.1.1.1"},
		{name: "A over IPv6 DNS", ipv6DNS: []string{"2606:4700:4700::1111"}, option: dnsfeature.IPOption{IPv4Enable: true}, wantAddress: "198.51.100.40", wantServer: "2606:4700:4700::1111"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dispatcher := &egressDNSDispatcher{
				requests: make(chan egressDNSRequest, 2),
				respond: func(_ coreNet.Destination, query *miekgdns.Msg) (*miekgdns.Msg, <-chan struct{}) {
					return makeEgressDNSAnswer(query, tt.wantAddress), nil
				},
			}
			server := newTestSystemEgressNameServer(func(context.Context) *egress.Snapshot {
				return newEgressTestSnapshot(1, tt.ipv4DNS, tt.ipv6DNS)
			}, dispatcher)
			ctx, cancel := context.WithTimeout(withSystemEgressCoreContext(context.Background()), 2*time.Second)
			t.Cleanup(dispatcher.close)
			defer cancel()
			ips, _, err := server.QueryIP(ctx, "family.example", tt.option)
			if err != nil {
				t.Fatalf("QueryIP failed: %v", err)
			}
			if len(ips) != 1 || ips[0].String() != tt.wantAddress {
				t.Fatalf("QueryIP returned %v, want %s", ips, tt.wantAddress)
			}
			request := awaitEgressDNSRequest(t, dispatcher.requests)
			if request.destination.Address.IP().String() != tt.wantServer {
				t.Fatalf("query used resolver %s, want %s", request.destination.Address, tt.wantServer)
			}
			wantType := uint16(miekgdns.TypeA)
			if tt.option.IPv6Enable {
				wantType = miekgdns.TypeAAAA
			}
			if request.qtype != wantType {
				t.Fatalf("wire query type = %d, want %d", request.qtype, wantType)
			}
		})
	}
}

func TestSystemEgressNameServerFallsBackAfterResolverDropsReplies(t *testing.T) {
	tests := []struct {
		name       string
		ipv4DNS    []string
		ipv6DNS    []string
		healthyDNS string
	}{
		{name: "next configured IPv4 resolver", ipv4DNS: []string{"1.1.1.1", "9.9.9.9"}, healthyDNS: "9.9.9.9"},
		{name: "IPv4 failure then IPv6 resolver", ipv4DNS: []string{"1.1.1.1"}, ipv6DNS: []string{"2606:4700:4700::1111"}, healthyDNS: "2606:4700:4700::1111"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dispatcher := &egressDNSDispatcher{
				requests: make(chan egressDNSRequest, 4),
				respond: func(destination coreNet.Destination, query *miekgdns.Msg) (*miekgdns.Msg, <-chan struct{}) {
					if destination.Address.IP().String() == "1.1.1.1" {
						return nil, nil // This selected DNS server silently drops every query.
					}
					return makeEgressDNSAnswer(query, "198.51.100.50"), nil
				},
			}
			server := newTestSystemEgressNameServer(func(context.Context) *egress.Snapshot {
				return newEgressTestSnapshot(20, tt.ipv4DNS, tt.ipv6DNS)
			}, dispatcher)
			t.Cleanup(dispatcher.close)
			type lookupResult struct {
				ips []net.IP
				err error
			}
			result := make(chan lookupResult, 1)
			go func() {
				ctx, cancel := context.WithTimeout(withSystemEgressCoreContext(context.Background()), 4*time.Second)
				defer cancel()
				ips, _, err := server.QueryIP(ctx, "fallback.example", dnsfeature.IPOption{IPv4Enable: true})
				result <- lookupResult{ips: ips, err: err}
			}()

			first := awaitEgressDNSRequestWithin(t, dispatcher.requests, time.Second)
			if first.destination.Address.IP().String() != "1.1.1.1" {
				t.Fatalf("first resolver = %s, want dropping resolver 1.1.1.1", first.destination.Address)
			}
			second := awaitEgressDNSRequestWithin(t, dispatcher.requests, 3*time.Second)
			if second.destination.Address.IP().String() != tt.healthyDNS {
				t.Fatalf("fallback resolver = %s, want %s", second.destination.Address, tt.healthyDNS)
			}
			select {
			case got := <-result:
				if got.err != nil {
					t.Fatalf("QueryIP failed after resolver fallback: %v", got.err)
				}
				if len(got.ips) != 1 || got.ips[0].String() != "198.51.100.50" {
					t.Fatalf("QueryIP returned %v, want healthy resolver answer 198.51.100.50", got.ips)
				}
			case <-time.After(4 * time.Second):
				t.Fatal("fallback lookup exceeded its bounded deadline")
			}
		})
	}
}
