package anytls

import (
	"context"
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

// clientSessionManager owns every authenticated session for one outbound.
// Healthy sessions may carry concurrent streams; idle expiry never closes a
// session with active streams.
type clientSessionManager struct {
	mu                sync.Mutex
	sessions          map[*Session]*managedSession
	c                 *Client
	padding           atomic.Pointer[PaddingFactory]
	idleCheckInterval time.Duration
	idleTimeout       time.Duration
	minIdleSession    uint32
	sequence          uint64
	stop              chan struct{}
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
	if m.stop == nil {
		m.stop = make(chan struct{})
	}
	stop := m.stop
	m.mu.Unlock()
	if padding != nil {
		m.padding.Store(padding)
	}
	go m.cleanupLoop(stop, check)
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
		if newest == nil || state.sequence > newest.sequence {
			newest = state
		}
	}
	return newest
}

func (m *clientSessionManager) dial(ctx context.Context, dialer internet.Dialer) (*managedSession, error) {
	raw, err := dialer.Dial(ctx, m.c.server.Destination)
	if err != nil {
		return nil, err
	}
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
	if err := WriteAuthPreface(raw, account, paddingLength); err != nil {
		_ = raw.Close()
		return nil, err
	}
	session := NewSession(raw)
	session.padding.Store(padding)
	session.SetPaddingCallback(func(next *PaddingFactory) { m.padding.Store(next) })
	if err := session.StartClient(padding); err != nil {
		_ = session.Close()
		return nil, err
	}
	go func() { _ = session.Serve() }()
	m.mu.Lock()
	m.sequence++
	state := &managedSession{session: session, sequence: m.sequence}
	m.sessions[session] = state
	m.mu.Unlock()
	return state, nil
}

func (m *clientSessionManager) openStream(ctx context.Context, dialer internet.Dialer) (*Stream, error) {
	m.mu.Lock()
	var state *managedSession
	if m.c != nil && !m.c.disableReuse {
		state = m.newestReusableLocked()
	}
	if state != nil {
		state.active++
		state.idleSince = time.Time{}
	}
	m.mu.Unlock()
	if state == nil {
		var err error
		state, err = m.dial(ctx, dialer)
		if err != nil {
			return nil, err
		}
		m.mu.Lock()
		state.active = 1
		m.mu.Unlock()
	}
	stream, err := state.session.NewStream()
	if err != nil {
		m.release(state, true)
		return nil, err
	}
	stream.onClose = func() { m.release(state, false) }
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
	closeSession := failed || m.c.disableReuse || state.session.closed.Load()
	shouldClose := false
	if state.active == 0 {
		state.idleSince = time.Now()
		if closeSession {
			delete(m.sessions, state.session)
			shouldClose = true
		}
	}
	m.mu.Unlock()
	if shouldClose {
		_ = state.session.Close()
	}
}

func (m *clientSessionManager) close() error {
	m.stopOnce.Do(func() {
		m.mu.Lock()
		if m.stop != nil {
			close(m.stop)
		}
		m.mu.Unlock()
	})
	m.mu.Lock()
	sessions := make([]*Session, 0, len(m.sessions))
	for session := range m.sessions {
		sessions = append(sessions, session)
	}
	m.sessions = make(map[*Session]*managedSession)
	m.mu.Unlock()
	var first error
	for _, session := range sessions {
		if err := session.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
