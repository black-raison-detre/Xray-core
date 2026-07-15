package anytls

import (
	"context"
	"io"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type Client struct {
	server        *protocol.ServerSpec
	policyManager policy.Manager
	manager       clientSessionManager
	padding       *PaddingFactory
	disableReuse  bool
}

func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	if config == nil || config.Server == nil {
		return nil, errors.New("no target server found")
	}
	ms, ok := session.StreamSettingsFromContext(ctx).(*internet.MemoryStreamConfig)
	if !ok || !hasRequiredStreamSecurity(ms) {
		return nil, errors.New("anytls requires TLS or REALITY transport security")
	}
	server, err := protocol.NewServerSpecFromPB(config.Server)
	if err != nil {
		return nil, err
	}
	v := core.MustFromContext(ctx)
	c := &Client{server: server, policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager), padding: DefaultPaddingFactory(), disableReuse: config.DisableSessionReuse}
	c.manager.c = c
	minIdleSession := uint32(5)
	if config.MinIdleSession != nil {
		minIdleSession = *config.MinIdleSession
	}
	c.manager.configure(time.Duration(config.IdleSessionCheckInterval), time.Duration(config.IdleSessionTimeout), minIdleSession, c.padding)
	return c, nil
}
func (c *Client) Close() error { return c.manager.close() }
func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	obs := session.OutboundsFromContext(ctx)
	if len(obs) == 0 || !obs[len(obs)-1].Target.IsValid() {
		return errors.New("target not specified")
	}
	ob := obs[len(obs)-1]
	ob.Name = "anytls"
	ob.CanSpliceCopy = 3
	st, err := c.manager.openStream(ctx, dialer)
	if err != nil {
		return err
	}
	defer st.Close()
	p := c.policyManager.ForLevel(c.server.User.Level)
	timer := signal.CancelAfterInactivity(ctx, func() { _ = st.Close() }, p.Timeouts.ConnectionIdle)
	defer timer.SetTimeout(0)
	if ob.Target.Network == net.Network_UDP {
		return c.processUDP(ctx, link, st, ob.Target, timer)
	}
	address, err := writeAddress(ob.Target, true)
	if err != nil {
		return err
	}
	if _, err = st.Write(address); err != nil {
		return err
	}
	if err := st.WaitSYNACKError(3 * time.Second); err != nil {
		return err
	}
	return runBridge(ctx, link, st, timer)
}

func runBridge(ctx context.Context, link *transport.Link, st io.ReadWriteCloser, timer *signal.ActivityTimer) error {
	uplink := func() error {
		return buf.Copy(link.Reader, buf.NewWriter(st), buf.UpdateActivity(timer))
	}
	downlink := func() error {
		return buf.Copy(buf.NewReader(st), link.Writer, buf.UpdateActivity(timer))
	}
	err := task.Run(ctx, task.OnSuccess(uplink, task.Close(link.Writer)), downlink)
	common.Must(common.Interrupt(link.Reader))
	common.Must(common.Interrupt(link.Writer))
	return err
}

func (c *Client) processUDP(ctx context.Context, link *transport.Link, st *Stream, d net.Destination, timer *signal.ActivityTimer) error {
	magic := net.TCPDestination(net.DomainAddress(UoTMagic), 0)
	address, err := writeAddress(magic, true)
	if err != nil {
		return err
	}
	if _, err := st.Write(address); err != nil {
		return err
	}
	u := NewUoTCodec(st, st)
	if err := u.WriteRequest(true, d); err != nil {
		return err
	}
	if err := st.WaitSYNACKError(3 * time.Second); err != nil {
		return err
	}
	downlink := func() error {
		for {
			b, e := u.ReadConnected()
			if e != nil {
				return e
			}
			payload := buf.FromBytes(b)
			payload.UDP = &d
			if e := link.Writer.WriteMultiBuffer(buf.MultiBuffer{payload}); e != nil {
				return e
			}
			timer.Update()
		}
	}
	uplink := func() error {
		for {
			mb, e := link.Reader.ReadMultiBuffer()
			if e != nil {
				return e
			}
			for i, b := range mb {
				e = u.WriteConnected(b.Bytes())
				b.Release()
				if e != nil {
					buf.ReleaseMulti(mb[i+1:])
					return e
				}
				timer.Update()
			}
		}
	}
	err = task.Run(ctx, task.OnSuccess(uplink, task.Close(link.Writer)), downlink)
	common.Must(common.Interrupt(link.Reader))
	common.Must(common.Interrupt(link.Writer))
	return err
}

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}
