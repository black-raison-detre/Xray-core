package anytls

import (
	"context"
	"io"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/transport/internet"
)

type managedSession struct {
	session   *Session
	sequence  uint64
	active    int
	idleSince time.Time
}

type pendingSessionConn struct {
	raw io.Closer
}

// clientSessionManager owns every authenticated session for one outbound.
// A session is reserved by one stream at a time and becomes reusable only
// after that stream closes.
type clientSessionManager struct {
	mu                sync.Mutex
	sessions          map[*Session]*managedSession
	pending           map[*pendingSessionConn]struct{}
	c                 *Client
	padding           atomic.Pointer[PaddingFactory]
	idleCheckInterval time.Duration
	idleTimeout       time.Duration
	minIdleSession    uint32
	sequence          uint64
	stop              chan struct{}
	shutdownCtx       context.Context
	shutdownCancel    context.CancelFunc
	closed            bool
	stopOnce          sync.Once
}

func (m *clientSessionManager) configure(check, timeout time.Duration, minIdle uint32, padding *PaddingFactory) {
	if check <= 5*time.Second {
		check = 30 * time.Second
	}
	if timeout <= 5*time.Second {
		timeout = 30 * time.Second
	}
	m.mu.Lock()
	m.idleCheckInterval = check
	m.idleTimeout = timeout
	m.minIdleSession = minIdle
	if m.sessions == nil {
		m.sessions = make(map[*Session]*managedSession)
	}
	if m.pending == nil {
		m.pending = make(map[*pendingSessionConn]struct{})
	}
	if m.stop == nil {
		m.stop = make(chan struct{})
	}
	if m.shutdownCtx == nil {
		m.shutdownCtx, m.shutdownCancel = context.WithCancel(context.Background())
	}
	stop := m.stop
	startCleanup := !m.closed && (m.c == nil || !m.c.disableReuse)
	m.mu.Unlock()
	if padding != nil {
		m.padding.Store(padding)
	}
	if startCleanup {
		go m.cleanupLoop(stop, check)
	}
}

func (m *clientSessionManager) cleanupLoop(stop <-chan struct{}, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			m.reap(now)
		case <-stop:
			return
		}
	}
}

func (m *clientSessionManager) currentPadding() *PaddingFactory {
	if p := m.padding.Load(); p != nil {
		return p
	}
	if m.c != nil && m.c.padding != nil {
		return m.c.padding
	}
	return DefaultPaddingFactory()
}

func (m *clientSessionManager) reap(now time.Time) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	var expired []*managedSession
	healthyIdle := uint32(0)
	for session, state := range m.sessions {
		if session.closed.Load() {
			delete(m.sessions, session)
			continue
		}
		if state.active != 0 {
			continue
		}
		if state.idleSince.IsZero() || now.Sub(state.idleSince) < m.idleTimeout {
			healthyIdle++
			continue
		}
		expired = append(expired, state)
	}
	sort.Slice(expired, func(i, j int) bool { return expired[i].sequence > expired[j].sequence })
	keep := uint32(0)
	if healthyIdle < m.minIdleSession {
		keep = m.minIdleSession - healthyIdle
	}
	var closing []*Session
	for i, state := range expired {
		if uint32(i) < keep {
			state.idleSince = now
			continue
		}
		delete(m.sessions, state.session)
		closing = append(closing, state.session)
	}
	m.mu.Unlock()
	for _, session := range closing {
		_ = session.Close()
	}
}

func (m *clientSessionManager) newestReusableLocked() *managedSession {
	var newest *managedSession
	for session, state := range m.sessions {
		if session.closed.Load() {
			delete(m.sessions, session)
			continue
		}
		if state.active != 0 || state.idleSince.IsZero() {
			continue
		}
		if newest == nil || state.sequence > newest.sequence {
			newest = state
		}
	}
	return newest
}

func (m *clientSessionManager) registerPending(raw io.Closer) *pendingSessionConn {
	pending := &pendingSessionConn{raw: raw}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		_ = closePendingConn(raw)
		return nil
	}
	if m.pending == nil {
		m.pending = make(map[*pendingSessionConn]struct{})
	}
	m.pending[pending] = struct{}{}
	m.mu.Unlock()
	return pending
}

func (m *clientSessionManager) unregisterPendingLocked(pending *pendingSessionConn) {
	if pending != nil {
		delete(m.pending, pending)
	}
}

func closePendingConn(raw io.Closer) error {
	if conn, ok := raw.(interface{ SetDeadline(time.Time) error }); ok {
		_ = conn.SetDeadline(time.Now())
	}
	return raw.Close()
}

func (m *clientSessionManager) dial(ctx context.Context, dialer internet.Dialer) (*managedSession, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, ErrSessionClosed
	}
	shutdownCtx := m.shutdownCtx
	m.mu.Unlock()

	dialCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stopCaller := context.AfterFunc(ctx, cancel)
	stopShutdown := func() bool { return false }
	if shutdownCtx != nil {
		stopShutdown = context.AfterFunc(shutdownCtx, cancel)
	}
	keepSessionContext := false
	defer func() {
		if !keepSessionContext {
			stopCaller()
			stopShutdown()
			cancel()
		}
	}()
	raw, err := dialer.Dial(dialCtx, m.c.server.Destination)
	if err != nil {
		m.mu.Lock()
		closed := m.closed
		m.mu.Unlock()
		if closed {
			return nil, ErrSessionClosed
		}
		return nil, err
	}
	pending := m.registerPending(raw)
	if pending == nil {
		return nil, ErrSessionClosed
	}
	stopPendingClose := context.AfterFunc(dialCtx, func() { _ = closePendingConn(raw) })
	defer func() {
		stopPendingClose()
		m.mu.Lock()
		m.unregisterPendingLocked(pending)
		m.mu.Unlock()
	}()

	account, ok := m.c.server.User.Account.(*MemoryAccount)
	if !ok {
		_ = raw.Close()
		return nil, ErrMalformedFrame
	}
	padding := m.currentPadding()
	paddingLength := 0
	if sizes := padding.RecordSizes(0); len(sizes) > 0 && sizes[0] > 0 {
		paddingLength = sizes[0]
	}
	var authErr error
	if conn, ok := raw.(interface{ SetWriteDeadline(time.Time) error }); ok {
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		authErr = WriteAuthPreface(raw, account, paddingLength)
		_ = conn.SetWriteDeadline(time.Time{})
	} else {
		authErr = WriteAuthPreface(raw, account, paddingLength)
	}
	stopPendingClose()
	if authErr != nil {
		_ = closePendingConn(raw)
		return nil, authErr
	}
	if err := dialCtx.Err(); err != nil {
		_ = closePendingConn(raw)
		return nil, err
	}
	session := NewSession(raw.(io.ReadWriteCloser))
	session.padding.Store(padding)
	session.SetPaddingCallback(func(next *PaddingFactory) { m.padding.Store(next) })
	session.onClose = func() {
		stopShutdown()
		cancel()
	}
	if err := session.StartClient(padding); err != nil {
		_ = session.Close()
		return nil, err
	}
	if !stopCaller() {
		if err := ctx.Err(); err != nil {
			_ = session.Close()
			return nil, err
		}
	}
	go func() { _ = session.Serve() }()

	m.mu.Lock()
	m.unregisterPendingLocked(pending)
	managerClosed := m.closed
	sessionClosed := session.closed.Load()
	dialErr := dialCtx.Err()
	if managerClosed || sessionClosed || dialErr != nil {
		m.mu.Unlock()
		_ = session.Close()
		if managerClosed {
			return nil, ErrSessionClosed
		}
		if dialErr != nil {
			return nil, dialErr
		}
		return nil, ErrSessionClosed
	}
	m.sequence++
	state := &managedSession{session: session, sequence: m.sequence, active: 1}
	m.sessions[session] = state
	m.mu.Unlock()
	keepSessionContext = true
	return state, nil
}

func (m *clientSessionManager) openStream(ctx context.Context, dialer internet.Dialer) (*Stream, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, ErrSessionClosed
	}
	var state *managedSession
	if m.c != nil && !m.c.disableReuse {
		state = m.newestReusableLocked()
	}
	if state != nil {
		state.active = 1
		state.idleSince = time.Time{}
	}
	m.mu.Unlock()
	if state == nil {
		var err error
		state, err = m.dial(ctx, dialer)
		if err != nil {
			return nil, err
		}
	}
	stream, err := state.session.newStreamWithClose(func() { m.release(state, false) })
	if err != nil {
		m.release(state, true)
		return nil, err
	}
	return stream, nil
}

func (m *clientSessionManager) release(state *managedSession, failed bool) {
	if state == nil {
		return
	}
	m.mu.Lock()
	if state.active > 0 {
		state.active--
	}
	disableReuse := m.c != nil && m.c.disableReuse
	closeSession := failed || disableReuse || m.closed || state.session.closed.Load()
	shouldClose := false
	if state.active == 0 {
		if closeSession {
			delete(m.sessions, state.session)
			shouldClose = !state.session.closed.Load()
		} else {
			state.idleSince = time.Now()
		}
	}
	m.mu.Unlock()
	if shouldClose {
		_ = state.session.Close()
	}
}

func (m *clientSessionManager) close() error {
	var sessions []*Session
	var pending []*pendingSessionConn
	m.stopOnce.Do(func() {
		m.mu.Lock()
		m.closed = true
		if m.stop != nil {
			close(m.stop)
		}
		if m.shutdownCancel != nil {
			m.shutdownCancel()
		}
		for session := range m.sessions {
			sessions = append(sessions, session)
		}
		for conn := range m.pending {
			pending = append(pending, conn)
		}
		m.sessions = make(map[*Session]*managedSession)
		m.pending = make(map[*pendingSessionConn]struct{})
		m.mu.Unlock()
	})
	var first error
	for _, conn := range pending {
		if err := closePendingConn(conn.raw); err != nil && first == nil {
			first = err
		}
	}
	for _, session := range sessions {
		if err := session.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
