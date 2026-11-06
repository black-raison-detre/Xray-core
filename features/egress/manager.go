package egress

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	refreshInterval      = 5 * time.Second
	refreshDebounce      = 100 * time.Millisecond
	refreshMaxDebounce   = time.Second
	forcedRefreshTimeout = 2 * time.Second
)

var (
	activeMu         sync.RWMutex
	activeManager    *Manager
	globalGeneration atomic.Uint64
)

// Manager owns one active TUN selection lifecycle. Its immutable snapshot is
// the same source used by the socket dialer and RoutingService status API.
type Manager struct {
	options Options

	snapshotMu sync.RWMutex
	snapshot   *Snapshot
	refreshMu  sync.Mutex

	refresh    chan struct{}
	force      chan chan struct{}
	stop       chan struct{}
	done       chan struct{}
	closeOnce  sync.Once
	stopNotify func()
}

// StartActive selects current adapters and starts notifications plus the
// five-second fallback refresh. It is intended for Windows TUN startup.
func StartActive(options Options) (*Manager, error) {
	if !platformSupported() {
		return nil, fmt.Errorf("active per-family egress binding is unsupported on this platform")
	}
	options = normalizeOptions(options)
	observation, collectErr := collect(options)
	if collectErr != nil && observation.Error == "" {
		observation.Error = collectErr.Error()
	}
	manager := &Manager{
		options: options,
		refresh: make(chan struct{}, 1),
		force:   make(chan chan struct{}, 1),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	initial := Select(observation, options, true)
	if initial.Error != "" {
		initial.State = "error"
	}
	initial.Generation = globalGeneration.Add(1)
	manager.snapshot = initial

	activeMu.Lock()
	if activeManager != nil {
		activeMu.Unlock()
		return nil, fmt.Errorf("an egress updater is already active")
	}
	activeManager = manager
	activeMu.Unlock()

	manager.stopNotify, _ = registerNotifications(manager.RequestRefresh)
	go manager.run()
	return manager, nil
}

// RequestRefresh schedules a coalesced refresh. It is safe to call from an OS
// notification callback.
func (m *Manager) RequestRefresh() {
	if m == nil {
		return
	}
	select {
	case <-m.stop:
		return
	default:
	}
	select {
	case m.refresh <- struct{}{}:
	default:
	}
}

// Refresh requests an immediate OS snapshot and waits no longer than the
// caller's deadline or the bounded refresh wait. A timeout returns the most
// recent cached snapshot, whose ObservedAt remains unchanged.
func (m *Manager) Refresh(ctx context.Context) {
	m.refreshWithTimeout(ctx, forcedRefreshTimeout)
}

func (m *Manager) refreshWithTimeout(ctx context.Context, timeout time.Duration) {
	if m == nil {
		return
	}
	completed := make(chan struct{})
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case m.force <- completed:
	case <-timer.C:
		return
	case <-m.stop:
		return
	case <-ctx.Done():
		return
	}
	select {
	case <-completed:
	case <-timer.C:
	case <-ctx.Done():
	case <-m.stop:
	}
}

// Snapshot returns a deep copy so callers cannot mutate the published state.
func (m *Manager) Snapshot() *Snapshot {
	if m == nil {
		return inactiveSnapshot()
	}
	m.snapshotMu.RLock()
	defer m.snapshotMu.RUnlock()
	return cloneSnapshot(m.snapshot)
}

// Closed reports whether this updater has cleared its published binding.
func (m *Manager) Closed() bool {
	if m == nil {
		return true
	}
	m.snapshotMu.RLock()
	defer m.snapshotMu.RUnlock()
	return m.snapshot == nil || m.snapshot.State == "inactive"
}

// BindingForNetwork returns the exact immutable family binding represented by
// the manager's published snapshot.
func (m *Manager) BindingForNetwork(network string) *Interface {
	if m == nil {
		return nil
	}
	m.snapshotMu.RLock()
	defer m.snapshotMu.RUnlock()
	if strings.HasSuffix(strings.ToLower(network), "6") {
		if m.snapshot == nil || m.snapshot.IPv6.State != "selected" {
			return nil
		}
		return copyInterface(m.snapshot.IPv6.Interface)
	}
	if m.snapshot == nil || m.snapshot.IPv4.State != "selected" {
		return nil
	}
	return copyInterface(m.snapshot.IPv4.Interface)
}

// Close stops OS notifications and polling, removes this updater from the
// process-wide API slot, and clears its published bindings.
func (m *Manager) Close() {
	if m == nil {
		return
	}
	m.closeOnce.Do(func() {
		if m.stopNotify != nil {
			m.stopNotify()
		}
		close(m.stop)
		<-m.done
		m.snapshotMu.Lock()
		m.snapshot = inactiveSnapshot()
		m.snapshotMu.Unlock()
		activeMu.Lock()
		if activeManager == m {
			activeManager = nil
		}
		activeMu.Unlock()
	})
}

func getActiveManager() *Manager {
	activeMu.RLock()
	defer activeMu.RUnlock()
	return activeManager
}

func (m *Manager) run() {
	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()
	defer close(m.done)
	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
			m.refreshSnapshot()
		case completed := <-m.force:
			m.refreshSnapshot()
			close(completed)
		case <-m.refresh:
			if !waitForNetworkChanges(m.stop, m.refresh, m.force, ticker.C, m.refreshSnapshot) {
				return
			}
			m.refreshSnapshot()
		}
	}
}

func waitForNetworkChanges(stop <-chan struct{}, refresh <-chan struct{}, force <-chan chan struct{}, fallback <-chan time.Time, refreshNow func()) bool {
	quietTimer := time.NewTimer(refreshDebounce)
	defer quietTimer.Stop()
	maxTimer := time.NewTimer(refreshMaxDebounce)
	defer maxTimer.Stop()
	for {
		select {
		case <-stop:
			return false
		case <-quietTimer.C:
			return true
		case <-maxTimer.C:
			return true
		case <-fallback:
			refreshNow()
		case completed := <-force:
			refreshNow()
			close(completed)
		case <-refresh:
			if !quietTimer.Stop() {
				select {
				case <-quietTimer.C:
				default:
				}
			}
			quietTimer.Reset(refreshDebounce)
		}
	}
}

func (m *Manager) refreshSnapshot() {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()
	observation, err := collect(m.options)
	if err != nil && observation.Error == "" {
		observation.Error = err.Error()
	}
	if observation.Error != "" || observation.ObservedAt.IsZero() {
		m.publishRefreshError(observation.Error)
		return
	}

	updated := Select(observation, m.options, true)
	m.snapshotMu.Lock()
	defer m.snapshotMu.Unlock()
	if selectionSignature(updated) != selectionSignature(m.snapshot) {
		updated.Generation = globalGeneration.Add(1)
	} else {
		updated.Generation = m.snapshot.Generation
	}
	m.snapshot = updated
}

func (m *Manager) publishRefreshError(message string) {
	if message == "" {
		message = "failed to refresh egress interfaces"
	}
	m.snapshotMu.Lock()
	defer m.snapshotMu.Unlock()
	updated := cloneSnapshot(m.snapshot)
	updated.State = "error"
	updated.Error = message
	m.snapshot = updated
}

func selectionSignature(snapshot *Snapshot) string {
	if snapshot == nil {
		return ""
	}
	copy := cloneSnapshot(snapshot)
	copy.Generation = 0
	copy.ObservedAt = time.Time{}
	copy.State = ""
	copy.Error = ""
	encoded, _ := json.Marshal(copy)
	return string(encoded)
}
