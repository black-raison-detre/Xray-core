package observatory

import (
	"context"
	"io"
	"net"
	"net/http"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	v2net "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/extension"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/tagged"
	"google.golang.org/protobuf/proto"
)

type Observer struct {
	config *Config
	ctx    context.Context

	statusLock sync.Mutex
	status     []*OutboundStatus

	finished  *done.Instance
	probeLock sync.Mutex
	clients   map[string]*probeClient
	closed    bool

	ohm        outbound.Manager
	dispatcher routing.Dispatcher
}

func (o *Observer) GetObservation(ctx context.Context) (proto.Message, error) {
	o.statusLock.Lock()
	defer o.statusLock.Unlock()
	return proto.Clone(&ObservationResult{Status: o.status}), nil
}

func (o *Observer) Type() interface{} {
	return extension.ObservatoryType()
}

func (o *Observer) Start() error {
	o.probeLock.Lock()
	defer o.probeLock.Unlock()
	if o.closed {
		return errors.New("observatory is closed")
	}
	if o.finished == nil && o.config != nil && len(o.config.SubjectSelector) != 0 {
		o.finished = done.New()
		go o.background()
	}
	return nil
}

func (o *Observer) Close() error {
	o.probeLock.Lock()
	defer o.probeLock.Unlock()
	o.closed = true
	if o.finished != nil {
		_ = o.finished.Close()
	}
	for tag, client := range o.clients {
		client.close()
		delete(o.clients, tag)
	}
	return nil
}

func (o *Observer) background() {
	for !o.finished.Done() {
		hs, ok := o.ohm.(outbound.HandlerSelector)
		if !ok {
			errors.LogInfo(o.ctx, "outbound.Manager is not a HandlerSelector")
			return
		}

		outbounds := hs.Select(o.config.SubjectSelector)

		o.clearRemovedOutbounds(outbounds)

		sleepTime := time.Second * 10
		if o.config.ProbeInterval != 0 {
			sleepTime = time.Duration(o.config.ProbeInterval)
		}

		if len(outbounds) == 0 {
			errors.LogWarning(o.ctx, "no outbound matches subjectSelector ", o.config.SubjectSelector)
			o.wait(sleepTime)
			continue
		}

		if !o.config.EnableConcurrency {
			sort.Strings(outbounds)
			for _, v := range outbounds {
				result := o.probe(v)
				o.updateStatusForResult(v, &result)
				if o.finished.Done() {
					return
				}
				if !o.wait(sleepTime) {
					return
				}
			}
			continue
		}

		ch := make(chan struct{}, len(outbounds))

		for _, v := range outbounds {
			go func(v string) {
				result := o.probe(v)
				o.updateStatusForResult(v, &result)
				ch <- struct{}{}
			}(v)
		}

		for range outbounds {
			select {
			case <-ch:
			case <-o.finished.Wait():
				return
			}
		}
		o.wait(sleepTime)
	}
}

func (o *Observer) wait(interval time.Duration) bool {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-o.finished.Wait():
		return false
	}
}

func (o *Observer) clearRemovedOutbounds(outbounds []string) {
	o.probeLock.Lock()
	for tag, client := range o.clients {
		if !slices.Contains(outbounds, tag) {
			client.close()
			delete(o.clients, tag)
		}
	}
	o.probeLock.Unlock()

	o.statusLock.Lock()
	defer o.statusLock.Unlock()
	if len(o.status) == 0 {
		return
	}
	var pruned []*OutboundStatus
	for _, status := range o.status {
		if slices.Contains(outbounds, status.OutboundTag) {
			pruned = append(pruned, status)
		}
	}
	o.status = pruned
}

// Each outbound owns its pool: sharing a transport across tags could reuse a
// connection without calling DialContext and therefore probe the wrong outbound.
type probeClient struct {
	sync.Mutex
	handler   outbound.Handler
	ctx       context.Context
	cancel    context.CancelFunc
	transport *http.Transport
	client    *http.Client
	errors    *errorCollector
}

func (c *probeClient) close() {
	c.cancel()
	c.transport.CloseIdleConnections()
}

type probeConn struct {
	net.Conn
	cancel context.CancelFunc
}

func (c *probeConn) Close() error {
	c.cancel()
	return c.Conn.Close()
}

func (o *Observer) clientForOutbound(tag string) (*probeClient, error) {
	o.probeLock.Lock()
	defer o.probeLock.Unlock()
	if o.closed {
		return nil, errors.New("observatory is closed")
	}
	handler := o.ohm.GetHandler(tag)
	if client := o.clients[tag]; client != nil {
		if handler != nil && client.handler == handler {
			return client, nil
		}
		// A removed/replaced handler must never inherit the old handler's pool.
		client.close()
		delete(o.clients, tag)
	}
	if handler == nil {
		return nil, errors.New("outbound no longer exists: ", tag)
	}
	ctx, cancel := context.WithCancel(o.ctx)
	client := &probeClient{handler: handler, ctx: ctx, cancel: cancel, errors: newErrorCollector()}
	client.transport = &http.Transport{
		DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
			dest, err := v2net.ParseDestination(network + ":" + addr)
			if err != nil {
				return nil, errors.New("cannot understand address").Base(err)
			}
			// Preserve the core's context values and the connection lifetime, while
			// still allowing the HTTP dial to be canceled before it completes.
			dialCtx, cancel := context.WithCancel(client.ctx)
			stop := context.AfterFunc(ctx, cancel)
			trackedCtx := session.TrackedConnectionError(dialCtx, client.errors)
			conn, err := tagged.Dialer(trackedCtx, o.dispatcher, dest, tag)
			stop()
			if err != nil {
				cancel()
				return nil, errors.New("cannot dial remote address ", dest).Base(err)
			}
			if err := dialCtx.Err(); err != nil {
				_ = conn.Close()
				cancel()
				return nil, err
			}
			return &probeConn{Conn: conn, cancel: cancel}, nil
		},
		TLSHandshakeTimeout: time.Second * 5,
		IdleConnTimeout:     time.Second * 90,
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
	}
	client.client = &http.Client{
		Transport: client.transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: time.Second * 5,
	}
	if o.clients == nil {
		o.clients = make(map[string]*probeClient)
	}
	o.clients[tag] = client
	return client, nil
}

func (o *Observer) probe(outbound string) ProbeResult {
	var GETTime time.Duration
	var underlyingError error
	err := func() error {
		client, err := o.clientForOutbound(outbound)
		if err != nil {
			return err
		}
		client.Lock()
		defer client.Unlock()
		client.errors.reset()
		defer func() { underlyingError = client.errors.UnderlyingError() }()
		startTime := time.Now()
		probeURL := "https://www.google.com/generate_204"
		if o.config.ProbeUrl != "" {
			probeURL = o.config.ProbeUrl
		}
		req, err := http.NewRequestWithContext(client.ctx, http.MethodGet, probeURL, nil)
		if err != nil {
			return errors.New("invalid probe URL").Base(err)
		}
		utils.TryDefaultHeadersWith(req.Header, "nav")
		response, err := client.client.Do(req)
		if err != nil {
			return errors.New("outbound failed to relay connection").Base(err)
		}
		endTime := time.Now()
		GETTime = endTime.Sub(startTime)
		// Reading small responses to EOF enables reuse beyond generate_204.
		// Bound the drain; large/unfinished bodies may close this connection.
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
		_ = response.Body.Close()
		return nil
	}()
	if err != nil {
		errorMessage := "the outbound " + outbound + " is dead: GET request failed:" + err.Error() + "with outbound handler report underlying connection failed"
		errors.LogInfoInner(o.ctx, underlyingError, errorMessage)
		return ProbeResult{Alive: false, LastErrorReason: errorMessage}
	}
	errors.LogInfo(o.ctx, "the outbound ", outbound, " is alive:", GETTime.Seconds())
	return ProbeResult{Alive: true, Delay: GETTime.Milliseconds()}
}

func (o *Observer) updateStatusForResult(outbound string, result *ProbeResult) {
	o.statusLock.Lock()
	defer o.statusLock.Unlock()
	var status *OutboundStatus
	if location := o.findStatusLocationLockHolderOnly(outbound); location != -1 {
		status = o.status[location]
	} else {
		status = &OutboundStatus{}
		o.status = append(o.status, status)
	}

	status.LastTryTime = time.Now().Unix()
	status.OutboundTag = outbound
	status.Alive = result.Alive
	if result.Alive {
		status.Delay = result.Delay
		status.LastSeenTime = status.LastTryTime
		status.LastErrorReason = ""
	} else {
		status.LastErrorReason = result.LastErrorReason
		status.Delay = 99999999
	}
}

func (o *Observer) findStatusLocationLockHolderOnly(outbound string) int {
	for i, v := range o.status {
		if v.OutboundTag == outbound {
			return i
		}
	}
	return -1
}

func New(ctx context.Context, config *Config) (*Observer, error) {
	var outboundManager outbound.Manager
	var dispatcher routing.Dispatcher
	err := core.RequireFeatures(ctx, func(om outbound.Manager, rd routing.Dispatcher) {
		outboundManager = om
		dispatcher = rd
	})
	if err != nil {
		return nil, errors.New("Cannot get depended features").Base(err)
	}
	return &Observer{
		config:     config,
		ctx:        ctx,
		ohm:        outboundManager,
		dispatcher: dispatcher,
	}, nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}
