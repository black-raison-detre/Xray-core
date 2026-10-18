package anytls

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	udp_proto "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/udp"
)

type Server struct {
	validator     *Validator
	policyManager policy.Manager
	padding       *PaddingFactory
}

func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	if config == nil {
		return nil, errors.New("nil anytls config")
	}
	ms, ok := session.StreamSettingsFromContext(ctx).(*internet.MemoryStreamConfig)
	if !ok || !hasRequiredStreamSecurity(ms) {
		return nil, errors.New("anytls requires TLS or REALITY transport security")
	}
	v := new(Validator)
	for _, user := range config.Users {
		u, e := user.ToMemoryUser()
		if e != nil {
			return nil, e
		}
		if e = v.Add(u); e != nil {
			return nil, e
		}
	}
	p := DefaultPaddingFactory()
	var e error
	if config.PaddingScheme != "" {
		p, e = NewPaddingFactory([]byte(config.PaddingScheme))
		if e != nil {
			return nil, e
		}
	}
	corev := core.MustFromContext(ctx)
	return &Server{validator: v, policyManager: corev.GetFeature(policy.ManagerType()).(policy.Manager), padding: p}, nil
}

func (s *Server) AddUser(_ context.Context, u *protocol.MemoryUser) error { return s.validator.Add(u) }

func (s *Server) RemoveUser(_ context.Context, email string) error {
	if !s.validator.Del(email) {
		return errors.New("user not found")
	}
	return nil
}

func (s *Server) GetUser(_ context.Context, email string) *protocol.MemoryUser {
	return s.validator.GetByEmail(email)
}
func (s *Server) GetUsers(_ context.Context) []*protocol.MemoryUser { return s.validator.GetAll() }
func (s *Server) GetUsersCount(context.Context) int64               { return s.validator.GetCount() }

func (s *Server) Network() []net.Network { return []net.Network{net.Network_TCP, net.Network_UNIX} }

func (s *Server) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	if network != net.Network_TCP && network != net.Network_UNIX {
		return errors.New("anytls supports TCP transport only")
	}
	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		return errors.New("missing inbound metadata")
	}
	inbound.Name = "anytls"
	inbound.CanSpliceCopy = 3
	handshakePolicy := s.policyManager.ForLevel(0)
	if err := conn.SetReadDeadline(time.Now().Add(handshakePolicy.Timeouts.Handshake)); err != nil {
		return errors.New("failed to set AnyTLS handshake deadline").Base(err)
	}
	user, e := ReadAuthPreface(conn, s.validator)
	if e != nil {
		return e
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return errors.New("failed to clear AnyTLS handshake deadline").Base(err)
	}
	inbound.User = user
	var ses *Session
	ses = NewServerSession(conn, func(st *Stream) { s.handleStream(ctx, ses, st, dispatcher, user) })
	ses.padding.Store(s.padding)
	return ses.Serve()
}

func (s *Server) handleStream(ctx context.Context, ses *Session, st *Stream, dispatcher routing.Dispatcher, user *protocol.MemoryUser) {
	defer st.Close()
	dest, err := readAddress(st, true)
	if err != nil {
		_ = ses.RejectStream(st, errors.New("invalid destination").Base(err))
		return
	}
	if dest.Address.String() == UoTMagic {
		if err := s.handleUoT(ctx, ses, st, dispatcher, user); err != nil {
			_ = st.Close()
		}
		return
	}
	probe, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		_ = ses.RejectStream(st, err)
		return
	}
	if err := ses.AcceptStream(st); err != nil {
		_ = st.Close()
		return
	}
	p := s.policyManager.ForLevel(user.Level)
	s.bridgeDispatched(ctx, p, st, probe)
}

func (s *Server) bridgeDispatched(ctx context.Context, p policy.Session, st io.ReadWriteCloser, link *transport.Link) {
	// copyTCP normally dispatches itself; this accepted link avoids a second route lookup.
	_ = copyTCPWithLink(ctx, p, st, link)
}

func copyTCPWithLink(ctx context.Context, p policy.Session, in io.ReadWriteCloser, link *transport.Link) error {
	return copyTCP(ctx, p, in, link, nil, net.Destination{})
}

func (s *Server) handleUoT(ctx context.Context, ses *Session, st *Stream, dispatcher routing.Dispatcher, user *protocol.MemoryUser) error {
	u := NewUoTCodec(st, st)
	connected, dest, err := u.ReadRequest()
	if err != nil {
		_ = ses.RejectStream(st, errors.New("invalid UoT request").Base(err))
		return nil
	}
	if !dest.IsValid() {
		_ = ses.RejectStream(st, errors.New("invalid UoT destination"))
		return nil
	}
	p := s.policyManager.ForLevel(user.Level)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := signal.CancelAfterInactivity(ctx, cancel, p.Timeouts.ConnectionIdle)
	defer timer.SetTimeout(0)
	if connected {
		link, err := dispatcher.Dispatch(ctx, dest)
		if err != nil {
			_ = ses.RejectStream(st, err)
			return nil
		}
		if err := ses.AcceptStream(st); err != nil {
			return err
		}
		downlink := func() error {
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
		uplink := func() error {
			for {
				b, e := u.ReadConnected()
				if e != nil {
					return e
				}
				payload := buf.FromBytes(b)
				payload.UDP = &dest
				if e = link.Writer.WriteMultiBuffer(buf.MultiBuffer{payload}); e != nil {
					return e
				}
				timer.Update()
			}
		}
		return task.Run(ctx, task.OnSuccess(uplink, task.Close(link.Writer)), downlink)
	}
	if err := ses.AcceptStream(st); err != nil {
		return err
	}
	d := newUoTUnconnectedDispatcher(dispatcher, func(packet *udp_proto.Packet) {
		defer packet.Payload.Release()
		if err := u.WriteUnconnected(packet.Source, packet.Payload.Bytes()); err != nil {
			cancel()
			return
		}
		timer.Update()
	})
	defer d.Close()
	for {
		dst, b, e := u.ReadUnconnected()
		if e != nil {
			return e
		}
		d.Dispatch(ctx, dst, buf.FromBytes(b))
		timer.Update()
	}
}

// uotUnconnectedDispatcher keeps one Xray UDP ray per destination. Xray's
// udp.Dispatcher intentionally binds to its first destination, while UoT v2
// unconnected streams may interleave packets for multiple destinations.
type uotUnconnectedDispatcher struct {
	mu         sync.Mutex
	dispatcher routing.Dispatcher
	callback   func(*udp_proto.Packet)
	rays       map[string]*udp.Dispatcher
	closed     bool
}

func newUoTUnconnectedDispatcher(dispatcher routing.Dispatcher, callback func(*udp_proto.Packet)) *uotUnconnectedDispatcher {
	return &uotUnconnectedDispatcher{
		dispatcher: dispatcher,
		callback:   callback,
		rays:       make(map[string]*udp.Dispatcher),
	}
}

func (d *uotUnconnectedDispatcher) Dispatch(ctx context.Context, destination net.Destination, payload *buf.Buffer) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		payload.Release()
		return
	}
	key := destination.String()
	ray := d.rays[key]
	if ray == nil {
		ray = udp.NewDispatcher(d.dispatcher, func(_ context.Context, packet *udp_proto.Packet) {
			d.callback(packet)
		})
		d.rays[key] = ray
	}
	d.mu.Unlock()
	ray.Dispatch(ctx, destination, payload)
}

func (d *uotUnconnectedDispatcher) Close() {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	d.closed = true
	rays := make([]*udp.Dispatcher, 0, len(d.rays))
	for _, ray := range d.rays {
		rays = append(rays, ray)
	}
	d.rays = nil
	d.mu.Unlock()
	for _, ray := range rays {
		ray.RemoveRay()
	}
}

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}
