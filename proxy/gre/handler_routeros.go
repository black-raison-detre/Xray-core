//go:build routeros_gre

package gre

import (
	"context"
	"math"
	"time"

	observatoryapp "github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/extension"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/tun"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const maxICMPProbeDelay = 30 * time.Second

type Handler struct {
	ctx             context.Context
	cancel          context.CancelFunc
	config          *Config
	stack           tun.Stack
	device          packetDevice
	policyManager   policy.Manager
	dispatcher      routing.Dispatcher
	tag             string
	sniffingRequest session.SniffingRequest
	uplinkCounter   stats.Counter
	downlinkCounter stats.Counter
	observatory     extension.Observatory
}

var _ common.Runnable = (*Handler)(nil)

func (h *Handler) Init(ctx context.Context, policyManager policy.Manager, dispatcher routing.Dispatcher) error {
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		h.tag = inbound.Tag
	}
	if content := session.ContentFromContext(ctx); content != nil {
		h.sniffingRequest = content.SniffingRequest
	}
	if h.config.GetIcmpMode() == IcmpMode_PROBE {
		observatory, ok := core.MustFromContext(ctx).GetFeature(extension.ObservatoryType()).(extension.Observatory)
		if !ok {
			return errors.New("GRE ICMP probe mode requires Observatory")
		}
		h.observatory = observatory
	}
	h.ctx, h.cancel = context.WithCancel(core.ToBackgroundDetachedContext(ctx))
	h.policyManager, h.dispatcher = policyManager, dispatcher
	if len(h.tag) > 0 && policyManager.ForSystem().Stats.InboundUplink {
		manager := core.MustFromContext(ctx).GetFeature(stats.ManagerType()).(stats.Manager)
		h.uplinkCounter, _ = manager.GetOrRegisterCounter("inbound>>>" + h.tag + ">>>traffic>>>uplink")
	}
	if len(h.tag) > 0 && policyManager.ForSystem().Stats.InboundDownlink {
		manager := core.MustFromContext(ctx).GetFeature(stats.ManagerType()).(stats.Manager)
		h.downlinkCounter, _ = manager.GetOrRegisterCounter("inbound>>>" + h.tag + ">>>traffic>>>downlink")
	}
	return nil
}

func (h *Handler) Start() error {
	runtimeConfig, err := makeRuntimeConfig(h.config)
	if err != nil {
		return err
	}
	device, err := createPacketDevice(h.ctx, runtimeConfig)
	if err != nil {
		return err
	}
	packetStack, err := tun.NewStack(h.ctx, tun.StackOptions{
		Tun:           device,
		MTU:           runtimeConfig.mtu,
		IdleTimeout:   h.policyManager.ForLevel(h.config.GetUserLevel()).Timeouts.ConnectionIdle,
		Remote:        true,
		ICMPEchoDelay: h.icmpEchoDelay,
	}, h)
	if err != nil {
		_ = device.Close()
		return err
	}
	if err := packetStack.Start(); err != nil {
		_ = packetStack.Close()
		_ = device.Close()
		return err
	}
	if err := device.Start(); err != nil {
		_ = packetStack.Close()
		_ = device.Close()
		return err
	}
	h.stack, h.device = packetStack, device
	errors.LogInfo(h.ctx, "[gre] userspace tunnel up: ", runtimeConfig.remote, " -> ", runtimeConfig.local, " mtu=", runtimeConfig.mtu)
	return nil
}

func (h *Handler) icmpEchoDelay() (time.Duration, bool) {
	if h.config.GetIcmpMode() != IcmpMode_PROBE {
		return 0, true
	}
	if h.observatory == nil {
		return 0, false
	}
	report, err := h.observatory.GetObservation(h.ctx)
	if err != nil {
		errors.LogInfoInner(h.ctx, err, "[gre][icmp] failed to read Observatory result")
		return 0, false
	}
	result, ok := report.(*observatoryapp.ObservationResult)
	if !ok {
		return 0, false
	}
	leastDelay := int64(math.MaxInt64)
	for _, status := range result.Status {
		if status != nil && status.Alive && status.Delay >= 0 && status.Delay < leastDelay {
			leastDelay = status.Delay
		}
	}
	if leastDelay == math.MaxInt64 || leastDelay > maxICMPProbeDelay.Milliseconds() {
		return 0, false
	}
	return time.Duration(leastDelay) * time.Millisecond, true
}

func (h *Handler) HandleConnection(conn net.Conn, destination net.Destination) {
	defer conn.Close()
	ctx, cancel := context.WithCancel(h.ctx)
	defer cancel()
	ctx = c.ContextWithID(ctx, session.NewID())
	remote := conn.RemoteAddr()
	if remote == nil {
		errors.LogInfo(h.ctx, "[gre] dropped quickly closed connection")
		return
	}
	source := net.DestinationFromAddr(remote)
	inbound := session.Inbound{Name: "gre", Tag: h.tag, CanSpliceCopy: 3, Source: source, User: &protocol.MemoryUser{Level: h.config.GetUserLevel()}}
	ctx = session.ContextWithInbound(ctx, &inbound)
	ctx = session.ContextWithContent(ctx, &session.Content{SniffingRequest: h.sniffingRequest})
	ctx = session.SubContextFromMuxInbound(ctx)
	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{From: source, To: destination, Status: log.AccessAccepted})
	errors.LogInfo(ctx, "processing from ", source, " to ", destination)
	// Preserve the shared stack's buf.Reader/buf.Writer paths and TCP half-close
	// behavior instead of wrapping the connection in a copying io adapter.
	reader := &buf.TimeoutWrapperReader{Reader: buf.NewReader(conn), Counter: h.uplinkCounter}
	writer := buf.NewWriter(conn)
	if destination.Network != net.Network_UDP {
		writer = &tun.TCPWriter{Writer: writer, Counter: h.downlinkCounter}
	} else if h.downlinkCounter != nil {
		writer = &greUDPStatsWriter{writer: writer, counter: h.downlinkCounter}
	}
	link := &transport.Link{Reader: reader, Writer: writer}
	if err := h.dispatcher.DispatchLink(ctx, destination, link); err != nil {
		errors.LogError(ctx, errors.New("connection closed").Base(err))
	}
}

type greUDPStatsWriter struct {
	writer  buf.Writer
	counter stats.Counter
}

func (w *greUDPStatsWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for len(mb) > 0 {
		remaining, packet := buf.SplitFirst(mb)
		size := packet.Len()
		if err := w.writer.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
			buf.ReleaseMulti(remaining)
			return err
		}
		w.counter.Add(int64(size))
		mb = remaining
	}
	return nil
}

func (h *Handler) Close() error {
	if h.cancel != nil {
		h.cancel()
	}
	return errors.Combine(common.CloseIfExists(h.stack), common.CloseIfExists(h.device))
}

func (*Handler) Network() []net.Network { return []net.Network{} }
func (*Handler) Process(context.Context, net.Network, stat.Connection, routing.Dispatcher) error {
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		handler := &Handler{config: config.(*Config)}
		err := core.RequireFeatures(ctx, func(policyManager policy.Manager, dispatcher routing.Dispatcher) error {
			return handler.Init(ctx, policyManager, dispatcher)
		})
		return handler, err
	}))
}
