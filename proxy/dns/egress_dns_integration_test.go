package dns

import (
	"context"
	"errors"
	stdnet "net"
	"sync/atomic"
	"testing"
	"time"

	miekgdns "github.com/miekg/dns"
	"github.com/xtls/xray-core/common/buf"
	coreNet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	dnsfeature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/egress"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
	"golang.org/x/net/dns/dnsmessage"
)

type processDNSLookup struct {
	domain string
	option dnsfeature.IPOption
}

type processDNSClient struct {
	lookups chan processDNSLookup
}

func (c *processDNSClient) Type() interface{} { return dnsfeature.ClientType() }
func (c *processDNSClient) Start() error      { return nil }
func (c *processDNSClient) Close() error      { return nil }
func (c *processDNSClient) LookupIP(domain string, option dnsfeature.IPOption) ([]coreNet.IP, uint32, error) {
	c.lookups <- processDNSLookup{domain: domain, option: option}
	if option.IPv4Enable {
		return []coreNet.IP{coreNet.ParseIP("198.18.0.7")}, 60, nil
	}
	return []coreNet.IP{coreNet.ParseIP("fc00::7")}, 60, nil
}

type processDNSDialer struct {
	destinations chan coreNet.Destination
	dialError    error
}

func (d *processDNSDialer) Dial(_ context.Context, destination coreNet.Destination) (stat.Connection, error) {
	d.destinations <- destination
	if d.dialError != nil {
		return nil, d.dialError
	}
	client, server := stdnet.Pipe()
	go func() {
		defer server.Close()
		wire := make([]byte, 4096)
		n, err := server.Read(wire)
		if err != nil || n == 0 {
			return
		}
		query := new(miekgdns.Msg)
		if err := query.Unpack(wire[:n]); err != nil || len(query.Question) == 0 {
			return
		}
		response := new(miekgdns.Msg)
		response.SetReply(query)
		rr, err := miekgdns.NewRR("wire.example. 30 IN TXT \"fixture\"")
		if err != nil {
			return
		}
		response.Answer = []miekgdns.RR{rr}
		packed, err := response.Pack()
		if err == nil {
			_, _ = server.Write(packed)
		}
	}()
	return client, nil
}

func (*processDNSDialer) DestIpAddress() coreNet.IP                             { return coreNet.ParseIP("192.0.2.10") }
func (*processDNSDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

func makeProxyEgressSnapshot() *egress.Snapshot {
	return &egress.Snapshot{
		State:      "active",
		Generation: 5,
		IPv4: egress.FamilyStatus{State: "selected", Interface: &egress.Interface{
			Name: "fixture-v4", LUID: "fixture-v4", DNSServers: []string{"8.8.4.4"},
		}},
		IPv6: egress.FamilyStatus{State: "selected", Interface: &egress.Interface{
			Name: "fixture-v6", LUID: "fixture-v6", DNSServers: []string{"2001:4860:4860::8844"},
		}},
	}
}

func runProcessDNSQuery(t *testing.T, handler *Handler, target coreNet.Destination, dialer internet.Dialer, qtype uint16) (*miekgdns.Msg, <-chan error) {
	t.Helper()
	incomingReader, incomingWriter := pipe.New(pipe.WithoutSizeLimit())
	outgoingReader, outgoingWriter := pipe.New(pipe.WithoutSizeLimit())
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: target}})
	done := make(chan error, 1)
	go func() {
		done <- handler.Process(ctx, &transport.Link{Reader: incomingReader, Writer: outgoingWriter}, dialer)
	}()
	t.Cleanup(func() {
		_ = incomingWriter.Close()
		outgoingReader.Interrupt()
	})

	query := new(miekgdns.Msg)
	query.Id = 0x4321
	query.RecursionDesired = true
	query.Question = []miekgdns.Question{{Name: "wire.example.", Qtype: qtype, Qclass: miekgdns.ClassINET}}
	wire, err := query.Pack()
	if err != nil {
		t.Fatalf("pack DNS query: %v", err)
	}
	if err := incomingWriter.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(wire)}); err != nil {
		t.Fatalf("write DNS query to Handler.Process: %v", err)
	}

	type readResult struct {
		message *miekgdns.Msg
		err     error
	}
	readDone := make(chan readResult, 1)
	go func() {
		multi, err := outgoingReader.ReadMultiBuffer()
		if err != nil {
			readDone <- readResult{err: err}
			return
		}
		defer buf.ReleaseMulti(multi)
		if len(multi) == 0 {
			readDone <- readResult{err: errors.New("empty DNS response")}
			return
		}
		message := new(miekgdns.Msg)
		if err := message.Unpack(multi[0].Bytes()); err != nil {
			readDone <- readResult{err: err}
			return
		}
		readDone <- readResult{message: message}
	}()
	select {
	case result := <-readDone:
		if result.err != nil {
			t.Fatalf("read DNS response from Handler.Process: %v", result.err)
		}
		return result.message, done
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Handler.Process DNS response")
		return nil, done
	}
}

func awaitProcessDNSDone(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Handler.Process returned an unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Handler.Process did not finish after the DNS exchange")
	}
}

func TestSystemEgressRewriteIsLazyAndLimitedToManagedPeerDNS(t *testing.T) {
	tests := []struct {
		name     string
		target   coreNet.Destination
		wantIP   string
		wantPort coreNet.Port
	}{
		{name: "IPv4 managed peer", target: coreNet.UDPDestination(coreNet.ParseAddress(egress.TUNPeerDNSIPv4), 53), wantIP: "8.8.4.4", wantPort: 1053},
		{name: "IPv6 managed peer", target: coreNet.UDPDestination(coreNet.ParseAddress(egress.TUNPeerDNSIPv6), 53), wantIP: "2001:4860:4860::8844", wantPort: 1053},
		{name: "explicit raw resolver", target: coreNet.UDPDestination(coreNet.ParseAddress("8.8.8.8"), 5353), wantIP: "8.8.8.8", wantPort: 5353},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dialer := &processDNSDialer{destinations: make(chan coreNet.Destination, 1)}
			handler := &Handler{
				egressSnapshot: func(context.Context) *egress.Snapshot { return makeProxyEgressSnapshot() },
				rewriteServer: coreNet.Destination{
					Network: coreNet.Network_UDP,
					Address: coreNet.DomainAddress(egress.SystemEgressDNSAddress),
					Port:    1053,
				},
				systemEgressRewrite: true,
				timeout:             time.Second,
				rules:               []*DNSRule{{action: RuleAction_Direct, qTypes: []uint16{uint16(dnsmessage.TypeTXT)}}},
			}
			response, done := runProcessDNSQuery(t, handler, tt.target, dialer, miekgdns.TypeTXT)
			if len(response.Answer) != 1 || response.Answer[0].Header().Rrtype != miekgdns.TypeTXT {
				t.Fatalf("Handler.Process response = %v, want one TXT answer", response.Answer)
			}
			select {
			case destination := <-dialer.destinations:
				if destination.Address.IP().String() != tt.wantIP || destination.Port != tt.wantPort {
					t.Fatalf("lazy dial destination = %s:%d, want %s:%d", destination.Address, destination.Port, tt.wantIP, tt.wantPort)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Handler.Process did not lazily dial the DNS transport")
			}
			awaitProcessDNSDone(t, done)
		})
	}
}

func TestSystemEgressDNSHijacksAAndAAAAWithoutPhysicalResolverDial(t *testing.T) {
	tests := []struct {
		name        string
		qtype       uint16
		wantIP      string
		wantV4      bool
		peerAddress string
	}{
		{name: "A", qtype: miekgdns.TypeA, wantIP: "198.18.0.7", wantV4: true, peerAddress: egress.TUNPeerDNSIPv4},
		{name: "AAAA", qtype: miekgdns.TypeAAAA, wantIP: "fc00::7", peerAddress: egress.TUNPeerDNSIPv6},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &processDNSClient{lookups: make(chan processDNSLookup, 1)}
			dialer := &processDNSDialer{destinations: make(chan coreNet.Destination, 1), dialError: errors.New("physical resolver dial must not occur")}
			var snapshotCalls atomic.Int32
			handler := &Handler{
				client: client,
				egressSnapshot: func(context.Context) *egress.Snapshot {
					snapshotCalls.Add(1)
					return &egress.Snapshot{State: "active"}
				},
				rewriteServer: coreNet.Destination{
					Network: coreNet.Network_UDP,
					Address: coreNet.DomainAddress(egress.SystemEgressDNSAddress),
					Port:    1053,
				},
				systemEgressRewrite: true,
				timeout:             100 * time.Millisecond,
			}
			target := coreNet.UDPDestination(coreNet.ParseAddress(tt.peerAddress), 53)
			response, done := runProcessDNSQuery(t, handler, target, dialer, tt.qtype)
			if len(response.Answer) != 1 {
				t.Fatalf("Handler.Process returned %d answers, want one fake/hijacked answer", len(response.Answer))
			}
			var answer string
			switch record := response.Answer[0].(type) {
			case *miekgdns.A:
				answer = record.A.String()
			case *miekgdns.AAAA:
				answer = record.AAAA.String()
			default:
				t.Fatalf("unexpected answer record type %T", response.Answer[0])
			}
			if answer != tt.wantIP {
				t.Fatalf("hijacked answer = %s, want %s", answer, tt.wantIP)
			}
			select {
			case lookup := <-client.lookups:
				if !lookup.option.FakeEnable || lookup.option.IPv4Enable != tt.wantV4 || lookup.option.IPv6Enable == tt.wantV4 {
					t.Fatalf("DNS client options = %+v, want FakeEnable and the requested answer family", lookup.option)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("A/AAAA hijack did not reach the DNS client")
			}
			select {
			case destination := <-dialer.destinations:
				t.Fatalf("A/AAAA hijack unexpectedly dialed physical DNS at %s", destination)
			default:
			}
			if calls := snapshotCalls.Load(); calls != 0 {
				t.Fatalf("A/AAAA hijack eagerly read TUN egress state %d times; want zero physical DNS lookups", calls)
			}
			awaitProcessDNSDone(t, done)
		})
	}
}

func TestSystemEgressRewriteAddressRequiresActiveAdapterDNS(t *testing.T) {
	for _, tc := range []struct {
		peer   string
		family string
	}{
		{peer: egress.TUNPeerDNSIPv4, family: "ipv4"},
		{peer: egress.TUNPeerDNSIPv6, family: "ipv6"},
	} {
		t.Run(tc.family, func(t *testing.T) {
			address, matched, err := systemEgressRewriteAddress(coreNet.ParseAddress(tc.peer), &egress.Snapshot{State: "active"})
			if !matched || err == nil || address != nil {
				t.Fatalf("peer rewrite with no selected %s DNS = %v, %v, %v; want matched error and no fallback address", tc.family, address, matched, err)
			}
		})
	}
}

func TestSystemEgressDNSPeersUseAvailableTransportFamily(t *testing.T) {
	for _, tc := range []struct {
		name string
		peer string
		ipv4 bool
		want string
	}{
		{name: "IPv6 peer with IPv4-only DNS", peer: egress.TUNPeerDNSIPv6, ipv4: true, want: "8.8.4.4"},
		{name: "IPv4 peer with IPv6-only DNS", peer: egress.TUNPeerDNSIPv4, want: "2001:4860:4860::8844"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := makeProxyEgressSnapshot()
			if tc.ipv4 {
				snapshot.IPv6 = egress.FamilyStatus{State: "unavailable"}
			} else {
				snapshot.IPv4 = egress.FamilyStatus{State: "unavailable"}
			}
			dialer := &processDNSDialer{destinations: make(chan coreNet.Destination, 1)}
			handler := &Handler{
				egressSnapshot:      func(context.Context) *egress.Snapshot { return snapshot },
				rewriteServer:       coreNet.Destination{Network: coreNet.Network_UDP, Address: coreNet.DomainAddress(egress.SystemEgressDNSAddress), Port: 1053},
				systemEgressRewrite: true, timeout: time.Second,
				rules: []*DNSRule{{action: RuleAction_Direct, qTypes: []uint16{uint16(dnsmessage.TypeTXT)}}},
			}
			response, done := runProcessDNSQuery(t, handler, coreNet.UDPDestination(coreNet.ParseAddress(tc.peer), 53), dialer, miekgdns.TypeTXT)
			if len(response.Answer) != 1 {
				t.Fatalf("forwarded DNS response=%v", response)
			}
			select {
			case destination := <-dialer.destinations:
				if destination.Address.IP().String() != tc.want || destination.Port != 1053 {
					t.Fatalf("physical DNS=%v want%v:1053", destination, tc.want)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("no physical DNS dial")
			}
			awaitProcessDNSDone(t, done)
		})
	}
}

var _ dnsfeature.Client = (*processDNSClient)(nil)
var _ internet.Dialer = (*processDNSDialer)(nil)
