package conf_test

import (
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/shadowsocksr"
)

func TestShadowsocksRCanonicalConfig(t *testing.T) {
	runMultiTestCase(t, []TestCase{{
		Input:  `{"address":"example.com","port":443,"method":" AES-256-CFB ","password":"secret","protocol":" AUTH_CHAIN_A ","protocolParam":"1001:user-key","obfs":" TLS1.2_TICKET_AUTH ","obfsParam":"www.example.com"}`,
		Parser: loadJSON(func() Buildable { return new(ShadowsocksRClientConfig) }),
		Output: &shadowsocksr.ClientConfig{Server: &protocol.ServerEndpoint{
			Address: &net.IPOrDomain{Address: &net.IPOrDomain_Domain{Domain: "example.com"}}, Port: 443,
			User: &protocol.User{Account: serial.ToTypedMessage(&shadowsocksr.Account{
				Password: "secret", Method: "aes-256-cfb", Protocol: "auth_chain_a", ProtocolParam: []byte("1001:user-key"), Obfs: "tls1.2_ticket_auth", ObfsParam: []byte("www.example.com"),
			})},
		}},
	}})
}

func TestShadowsocksRServersAndAliases(t *testing.T) {
	runMultiTestCase(t, []TestCase{{
		Input:  `{"servers":[{"address":"127.0.0.1","port":8388,"method":"rc4-md5","password":"secret","protocol_param":"2:key:with:colons","obfs_param":"a.example,b.example"}]}`,
		Parser: loadJSON(func() Buildable { return new(ShadowsocksRClientConfig) }),
		Output: &shadowsocksr.ClientConfig{Server: &protocol.ServerEndpoint{
			Address: &net.IPOrDomain{Address: &net.IPOrDomain_Ip{Ip: []byte{127, 0, 0, 1}}}, Port: 8388,
			User: &protocol.User{Account: serial.ToTypedMessage(&shadowsocksr.Account{Password: "secret", Method: "rc4-md5", Protocol: "origin", ProtocolParam: []byte("2:key:with:colons"), Obfs: "plain", ObfsParam: []byte("a.example,b.example")})},
		}},
	}})
}

func TestShadowsocksRRejectsAmbiguousEndpointsAndParameters(t *testing.T) {
	cases := []string{
		`{"address":"example.com","port":1,"method":"none","password":"x","servers":[{"address":"example.net","port":2,"method":"none","password":"x"}]}`,
		`{"servers":[{"address":"a","port":1,"method":"none","password":"x"},{"address":"b","port":2,"method":"none","password":"x"}]}`,
		`{"address":"example.com","port":1,"method":"none","password":"x","protocolParam":"a","protocol_param":"b"}`,
		`{"address":"example.com","port":1,"method":"none","password":"x","obfsParam":"a","obfs_param":"b"}`,
	}
	for _, input := range cases {
		if _, err := loadJSON(func() Buildable { return new(ShadowsocksRClientConfig) })(input); err == nil {
			t.Fatalf("accepted invalid config: %s", input)
		}
	}
}

func TestShadowsocksRRequiredFieldsAndRegistry(t *testing.T) {
	for _, input := range []string{
		`{"port":1,"method":"none","password":"x"}`,
		`{"address":"a","method":"none","password":"x"}`,
		`{"address":"a","port":1,"password":"x"}`,
		`{"address":"a","port":1,"method":"none"}`,
		`{"address":"a","port":1,"method":"aes-256-gcm","password":"x"}`,
		`{"address":"a","port":1,"method":"none","password":"x","protocol":"auth_simple"}`,
		`{"address":"a","port":1,"method":"none","password":"x","obfs":"verify_simple"}`,
	} {
		if _, err := loadJSON(func() Buildable { return new(ShadowsocksRClientConfig) })(input); err == nil {
			t.Fatalf("accepted invalid config: %s", input)
		}
	}
	if _, err := (&InboundDetourConfig{Protocol: "shadowsocksr", PortList: &PortList{Range: []PortRange{{From: 1, To: 1}}}}).Build(); err == nil || !strings.Contains(strings.ToLower(err.Error()), "unknown") {
		t.Fatalf("SSR inbound unexpectedly registered: %v", err)
	}
}
