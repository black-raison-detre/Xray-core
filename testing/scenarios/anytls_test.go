package scenarios

import (
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/anytls"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/sync/errgroup"
)

func anyTLSConfigs(serverPort, clientPort net.Port, destination net.Destination, network net.Network, allowInsecure bool) (*core.Config, *core.Config) {
	certificate, certificateHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	account := serial.ToTypedMessage(&anytls.Account{Password: "anytls-password"})
	clientTLS := &tls.Config{PinnedPeerCertSha256: [][]byte{certificateHash[:]}}
	if allowInsecure {
		clientTLS = &tls.Config{AllowInsecure: true}
	}
	serverConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
				Listen:   net.NewIPOrDomain(net.LocalHostIP),
				StreamSettings: &internet.StreamConfig{
					SecurityType: serial.GetMessageType(&tls.Config{}),
					SecuritySettings: []*serial.TypedMessage{serial.ToTypedMessage(&tls.Config{
						Certificate: []*tls.Certificate{tls.ParseCertificate(certificate)},
					})},
				},
			}),
			ProxySettings: serial.ToTypedMessage(&anytls.ServerConfig{Users: []*protocol.User{{
				Account: account,
				Level:   1,
			}}}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			ProxySettings: serial.ToTypedMessage(&freedom.Config{
				FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
			}),
		}},
	}
	clientConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
				Listen:   net.NewIPOrDomain(net.LocalHostIP),
			}),
			ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
				RewriteAddress:  net.NewIPOrDomain(destination.Address),
				RewritePort:     uint32(destination.Port),
				AllowedNetworks: []net.Network{network},
			}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			ProxySettings: serial.ToTypedMessage(&anytls.ClientConfig{
				Server: &protocol.ServerEndpoint{
					Address: net.NewIPOrDomain(net.LocalHostIP),
					Port:    uint32(serverPort),
					User:    &protocol.User{Account: account, Level: 1},
				},
			}),
			SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
				StreamSettings: &internet.StreamConfig{
					SecurityType:     serial.GetMessageType(&tls.Config{}),
					SecuritySettings: []*serial.TypedMessage{serial.ToTypedMessage(clientTLS)},
				},
			}),
		}},
	}
	return serverConfig, clientConfig
}

func TestAnyTLSAllowInsecure(t *testing.T) {
	echo := tcp.Server{MsgProcessor: xor}
	destination, err := echo.Start()
	common.Must(err)
	defer echo.Close()

	serverPort, clientPort := tcp.PickPort(), tcp.PickPort()
	serverConfig, clientConfig := anyTLSConfigs(serverPort, clientPort, destination, net.Network_TCP, true)
	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	if err := testTCPConn(clientPort, 1024, 10*time.Second)(); err != nil {
		t.Fatal(err)
	}
}

func TestAnyTLSTCP(t *testing.T) {
	echo := tcp.Server{MsgProcessor: xor}
	destination, err := echo.Start()
	common.Must(err)
	defer echo.Close()

	serverPort, clientPort := tcp.PickPort(), tcp.PickPort()
	serverConfig, clientConfig := anyTLSConfigs(serverPort, clientPort, destination, net.Network_TCP, false)
	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	var group errgroup.Group
	for range 3 {
		group.Go(testTCPConn(clientPort, 1024*1024, 20*time.Second))
	}
	if err := group.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestAnyTLSUoT(t *testing.T) {
	echo := udp.Server{MsgProcessor: xor}
	destination, err := echo.Start()
	common.Must(err)
	defer echo.Close()

	serverPort, clientPort := tcp.PickPort(), udp.PickPort()
	serverConfig, clientConfig := anyTLSConfigs(serverPort, clientPort, destination, net.Network_UDP, false)
	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	var group errgroup.Group
	for range 3 {
		group.Go(testUDPConn(clientPort, 1024, 10*time.Second))
	}
	if err := group.Wait(); err != nil {
		t.Fatal(err)
	}
}
