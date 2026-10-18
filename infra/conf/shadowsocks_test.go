package conf_test

import (
	"fmt"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/shadowsocks"
)

func TestShadowsocksOutboundAcceptsAllLegacyMethods(t *testing.T) {
	methods := []string{"none", "table", "rc4", "rc4-md5-6", "rc4-md5", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "bf-cfb", "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb", "cast5-cfb", "des-cfb", "idea-cfb", "rc2-cfb", "seed-cfb", "salsa20", "chacha20", "chacha20-ietf"}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			input := fmt.Sprintf(`{"address":"example.com","port":8388,"method":%q,"password":"secret"}`, method)
			if _, err := loadJSON(func() Buildable { return new(ShadowsocksClientConfig) })(input); err != nil {
				t.Fatal(err)
			}
			inbound := fmt.Sprintf(`{"method":%q,"password":"secret"}`, method)
			if _, err := loadJSON(func() Buildable { return new(ShadowsocksServerConfig) })(inbound); err == nil {
				t.Fatal("legacy inbound was accepted")
			}
		})
	}
}

func TestShadowsocksServerConfigParsing(t *testing.T) {
	creator := func() Buildable {
		return new(ShadowsocksServerConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"method": "aes-256-GCM",
				"password": "xray-password"
			}`,
			Parser: loadJSON(creator),
			Output: &shadowsocks.ServerConfig{
				Users: []*protocol.User{{
					Account: serial.ToTypedMessage(&shadowsocks.Account{
						CipherType: shadowsocks.CipherType_AES_256_GCM,
						Password:   "xray-password",
					}),
				}},
				Network: []net.Network{net.Network_TCP},
			},
		},
	})
}
