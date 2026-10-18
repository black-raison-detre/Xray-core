package conf_test

import (
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/anytls"
)

func anyTLSUint32(value uint32) *uint32 { return &value }

func TestAnyTLSOutboundDefaults(t *testing.T) {
	runMultiTestCase(t, []TestCase{{
		Input:  `{"address":"example.com","port":443,"password":"password","email":"user@example.com","level":1}`,
		Parser: loadJSON(func() Buildable { return new(AnyTLSClientConfig) }),
		Output: &anytls.ClientConfig{
			Server: &protocol.ServerEndpoint{
				Address: &net.IPOrDomain{Address: &net.IPOrDomain_Domain{Domain: "example.com"}},
				Port:    443,
				User: &protocol.User{
					Level:   1,
					Email:   "user@example.com",
					Account: serial.ToTypedMessage(&anytls.Account{Password: "password"}),
				},
			},
			IdleSessionCheckInterval: int64(30 * time.Second),
			IdleSessionTimeout:       int64(30 * time.Second),
			MinIdleSession:           anyTLSUint32(5),
		},
	}})
}

func TestAnyTLSInboundClientsAlias(t *testing.T) {
	runMultiTestCase(t, []TestCase{{
		Input:  `{"clients":[{"password":"password","email":"user@example.com","level":1}],"paddingScheme":"stop=1\n0=30-30"}`,
		Parser: loadJSON(func() Buildable { return new(AnyTLSServerConfig) }),
		Output: &anytls.ServerConfig{
			PaddingScheme: "stop=1\n0=30-30",
			Users: []*protocol.User{{
				Level:   1,
				Email:   "user@example.com",
				Account: serial.ToTypedMessage(&anytls.Account{Password: "password"}),
			}},
		},
	}})
}

func TestAnyTLSInboundRejectsUsersAndClientsTogether(t *testing.T) {
	_, err := (&AnyTLSServerConfig{
		Users:   []*AnyTLSUserConfig{{Password: "one"}},
		Clients: []*AnyTLSUserConfig{},
	}).Build()
	if err == nil {
		t.Fatal("AnyTLS inbound accepted both users and clients")
	}
}

func TestAnyTLSAllowsZeroMinimumIdleSessions(t *testing.T) {
	runMultiTestCase(t, []TestCase{{
		Input:  `{"address":"example.com","port":443,"password":"password","minIdleSession":0}`,
		Parser: loadJSON(func() Buildable { return new(AnyTLSClientConfig) }),
		Output: &anytls.ClientConfig{
			Server: &protocol.ServerEndpoint{
				Address: &net.IPOrDomain{Address: &net.IPOrDomain_Domain{Domain: "example.com"}},
				Port:    443,
				User: &protocol.User{
					Account: serial.ToTypedMessage(&anytls.Account{Password: "password"}),
				},
			},
			IdleSessionCheckInterval: int64(30 * time.Second),
			IdleSessionTimeout:       int64(30 * time.Second),
			MinIdleSession:           anyTLSUint32(0),
		},
	}})
}

func TestAnyTLSRejectsShortIdleSessions(t *testing.T) {
	for _, field := range []string{"idleSessionCheckInterval", "idleSessionTimeout"} {
		t.Run(field, func(t *testing.T) {
			_, err := loadJSON(func() Buildable { return new(AnyTLSClientConfig) })(`{"address":"example.com","port":443,"password":"password","` + field + `":"5s"}`)
			if err == nil {
				t.Fatal("Build() succeeded for an idle-session duration of 5s")
			}
		})
	}
}

func TestAnyTLSDetourRequirements(t *testing.T) {
	if _, err := (&OutboundDetourConfig{Protocol: "anytls"}).Build(); err == nil {
		t.Fatal("AnyTLS outbound without stream security was accepted")
	}
	if _, err := (&OutboundDetourConfig{
		Protocol:      "anytls",
		StreamSetting: &StreamConfig{Security: "tls"},
		MuxSettings:   &MuxConfig{Enabled: true},
	}).Build(); err == nil {
		t.Fatal("AnyTLS outbound with mux.enabled was accepted")
	}
	if _, err := (&InboundDetourConfig{
		Protocol: "anytls",
		PortList: &PortList{Range: []PortRange{{
			From: 443,
			To:   443,
		}}},
	}).Build(); err == nil {
		t.Fatal("AnyTLS inbound without stream security was accepted")
	}
}
