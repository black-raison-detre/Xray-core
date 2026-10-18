package shadowsocksr

import (
	"context"
	"crypto/rand"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	ssrobfs "github.com/xtls/xray-core/proxy/shadowsocksr/internal/obfs"
	ssrprotocol "github.com/xtls/xray-core/proxy/shadowsocksr/internal/protocol"
	"github.com/xtls/xray-core/proxy/shadowsocksr/internal/ssr"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type Client struct {
	server        *protocol.ServerSpec
	account       *MemoryAccount
	policyManager policy.Manager
	protocolData  interface{}
	obfsData      interface{}
	udp           *udpCodec
	globalMu      sync.Mutex
}

func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	if config.Server == nil {
		return nil, errors.New("no ShadowsocksR server configured")
	}
	server, err := protocol.NewServerSpecFromPB(config.Server)
	if err != nil {
		return nil, errors.New("invalid ShadowsocksR server").Base(err)
	}
	account, ok := server.User.Account.(*MemoryAccount)
	if !ok {
		return nil, errors.New("invalid ShadowsocksR account")
	}
	info := &ssr.ServerInfo{Host: server.Destination.Address.String(), Port: uint16(server.Destination.Port), Key: account.Cipher.Key(), KeyLen: len(account.Cipher.Key()), Random: rand.Reader, Now: time.Now, TcpMss: 1460}
	p := ssrprotocol.NewProtocol(account.Protocol)
	o := ssrobfs.NewObfs(account.Obfs)
	if p == nil || o == nil {
		return nil, errors.New("unsupported ShadowsocksR protocol or obfs")
	}
	info.Param = string(account.ProtocolParam)
	p.SetServerInfo(info)
	protocolData := p.GetData()
	info.Param = string(account.ObfsParam)
	o.SetServerInfo(info)
	obfsData := o.GetData()
	udpProtocol := ssrprotocol.NewProtocol(account.Protocol)
	info.Param = string(account.ProtocolParam)
	udpProtocol.SetServerInfo(info)
	udpProtocol.SetData(protocolData)
	v := core.MustFromContext(ctx)
	return &Client{server: server, account: account, policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager), protocolData: protocolData, obfsData: obfsData, udp: &udpCodec{account: account, protocol: udpProtocol}}, nil
}

func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified")
	}
	ob.Name = "shadowsocksr"
	ob.CanSpliceCopy = 3
	target := ob.Target
	serverDest := c.server.Destination
	serverDest.Network = target.Network
	var conn stat.Connection
	if err := retry.ExponentialBackoff(5, 100).On(func() error {
		raw, err := dialer.Dial(ctx, serverDest)
		if err == nil {
			conn = raw
		}
		return err
	}); err != nil {
		return errors.New("failed to connect to ShadowsocksR server").Base(err)
	}
	defer conn.Close()
	errors.LogInfo(ctx, "tunneling request via ShadowsocksR to ", target)
	level := uint32(0)
	if c.server.User != nil {
		level = c.server.User.Level
	}
	sessionPolicy := c.policyManager.ForLevel(level)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)
	if target.Network == xnet.Network_TCP {
		session, err := newSessionConn(conn, c.account, serverDest, target, c.protocolData, c.obfsData, &c.globalMu)
		if err != nil {
			return errors.New("initialize ShadowsocksR session").Base(err)
		}
		requestDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
			writer := buf.NewWriter(session)
			if err := buf.CopyOnceTimeout(link.Reader, writer, 100*time.Millisecond); err != nil && err != buf.ErrNotTimeoutReader && err != buf.ErrReadTimeout {
				return err
			}
			return buf.Copy(link.Reader, writer, buf.UpdateActivity(timer))
		}
		responseDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
			return buf.Copy(buf.NewReader(session), link.Writer, buf.UpdateActivity(timer))
		}
		if err := task.Run(ctx, requestDone, task.OnSuccess(responseDone, task.Close(link.Writer))); err != nil {
			return errors.New("ShadowsocksR connection ends").Base(err)
		}
		return nil
	}
	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		return buf.Copy(link.Reader, &udpWriter{Writer: conn, codec: c.udp, destination: target}, buf.UpdateActivity(timer))
	}
	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		return buf.Copy(&udpReader{Reader: conn, codec: c.udp}, link.Writer, buf.UpdateActivity(timer))
	}
	if err := task.Run(ctx, requestDone, task.OnSuccess(responseDone, task.Close(link.Writer))); err != nil {
		return errors.New("ShadowsocksR UDP connection ends").Base(err)
	}
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}
