package dns

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
	featuresdns "github.com/xtls/xray-core/features/dns"
	"golang.org/x/net/dns/dnsmessage"
)

type dnsReplySizeClient struct {
	ips     []xnet.IP
	domain  string
	options featuresdns.IPOption
}

func (c *dnsReplySizeClient) Type() interface{} { return (*dnsReplySizeClient)(nil) }

func (*dnsReplySizeClient) Start() error { return nil }

func (*dnsReplySizeClient) Close() error { return nil }

func (c *dnsReplySizeClient) LookupIP(domain string, options featuresdns.IPOption) ([]xnet.IP, uint32, error) {
	c.domain = domain
	c.options = options
	return c.ips, 60, nil
}

type dnsReplySizeWriter struct {
	messages [][]byte
}

func (w *dnsReplySizeWriter) WriteMessage(message *buf.Buffer) error {
	w.messages = append(w.messages, append([]byte(nil), message.Bytes()...))
	message.Release()
	return nil
}

func TestHandleIPQueryReplySize(t *testing.T) {
	tests := []struct {
		name         string
		qType        dnsmessage.Type
		ip           string
		count        int
		wantOversize bool
	}{
		{name: "A normal", qType: dnsmessage.TypeA, ip: "192.0.2.1", count: 1},
		{name: "A oversized", qType: dnsmessage.TypeA, ip: "192.0.2.1", count: 600, wantOversize: true},
		{name: "AAAA normal", qType: dnsmessage.TypeAAAA, ip: "2001:db8::1", count: 1},
		{name: "AAAA oversized", qType: dnsmessage.TypeAAAA, ip: "2001:db8::1", count: 400, wantOversize: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ip := xnet.ParseIP(test.ip)
			if ip == nil {
				t.Fatalf("invalid test IP %q", test.ip)
			}
			ips := make([]xnet.IP, test.count)
			for i := range ips {
				ips[i] = ip
			}

			client := &dnsReplySizeClient{ips: ips}
			writer := new(dnsReplySizeWriter)
			ctx, cancel := context.WithCancel(context.Background())
			timer := signal.CancelAfterInactivity(ctx, cancel, time.Hour)
			defer timer.SetTimeout(0)
			defer cancel()

			h := &Handler{client: client}
			h.handleIPQuery(0x1234, test.qType, "example.com.", writer, timer)

			wantIPv4 := test.qType == dnsmessage.TypeA
			if client.domain != "example.com." {
				t.Errorf("LookupIP domain = %q, want example.com.", client.domain)
			}
			if client.options.IPv4Enable != wantIPv4 || client.options.IPv6Enable == wantIPv4 || !client.options.FakeEnable {
				t.Errorf("LookupIP options = %+v, want IPv4Enable=%t IPv6Enable=%t FakeEnable=true", client.options, wantIPv4, !wantIPv4)
			}

			if test.wantOversize {
				if len(writer.messages) != 0 {
					t.Fatalf("oversized response wrote %d messages, want none", len(writer.messages))
				}
				if ctx.Err() != context.Canceled {
					t.Errorf("oversized response context error = %v, want cancellation", ctx.Err())
				}
				return
			}

			if len(writer.messages) != 1 {
				t.Fatalf("writer received %d messages, want 1", len(writer.messages))
			}
			var response dnsmessage.Message
			if err := response.Unpack(writer.messages[0]); err != nil {
				t.Fatalf("unpack DNS response: %v", err)
			}
			if response.Header.ID != 0x1234 || len(response.Questions) != 1 || response.Questions[0].Type != test.qType {
				t.Errorf("response header/questions = %+v / %+v, want ID 0x1234 and one %v question", response.Header, response.Questions, test.qType)
			}
			if len(response.Answers) != 1 {
				t.Fatalf("response has %d answers, want 1", len(response.Answers))
			}
			if got := response.Answers[0].Header.Type; got != test.qType {
				t.Errorf("answer type = %v, want %v", got, test.qType)
			}
			switch body := response.Answers[0].Body.(type) {
			case *dnsmessage.AResource:
				if test.qType != dnsmessage.TypeA || string(body.A[:]) != string(ip.To4()) {
					t.Errorf("A answer = %v, want %v", body.A, ip.To4())
				}
			case *dnsmessage.AAAAResource:
				if test.qType != dnsmessage.TypeAAAA || string(body.AAAA[:]) != string(ip.To16()) {
					t.Errorf("AAAA answer = %v, want %v", body.AAAA, ip.To16())
				}
			default:
				t.Errorf("answer body has type %T, want A/AAAA resource", response.Answers[0].Body)
			}
		})
	}
}
