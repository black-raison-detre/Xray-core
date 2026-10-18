package observatory

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/features/outbound"
)

type emptySelectingManager struct {
	outbound.Manager
	selects  atomic.Int64
	selected chan struct{}
}

func (m *emptySelectingManager) Select([]string) []string {
	if m.selects.Add(1) == 1 {
		close(m.selected)
	}
	return nil
}

func TestObserverBackgroundWaitsWhenNoOutboundMatches(t *testing.T) {
	manager := &emptySelectingManager{selected: make(chan struct{})}
	observer := &Observer{
		config: &Config{
			SubjectSelector: []string{"missing"},
			ProbeInterval:   int64(100 * time.Millisecond),
		},
		ctx:      context.Background(),
		finished: done.New(),
		ohm:      manager,
	}
	t.Cleanup(func() { _ = observer.finished.Close() })
	stopped := make(chan struct{})
	go func() {
		observer.background()
		close(stopped)
	}()

	select {
	case <-manager.selected:
	case <-time.After(time.Second):
		t.Fatal("observer did not select outbounds")
	}
	time.Sleep(20 * time.Millisecond)
	if got := manager.selects.Load(); got != 1 {
		t.Fatalf("outbound selections during one probe interval = %d, want 1", got)
	}

	if err := observer.finished.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("observer did not stop after close")
	}
}

func TestObserverGetObservationReturnsSnapshot(t *testing.T) {
	observer := &Observer{status: []*OutboundStatus{{OutboundTag: "proxy", Alive: true, Delay: 42}}}

	report, err := observer.GetObservation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	observer.status[0].Delay = 99

	got := report.(*ObservationResult).Status[0].Delay
	if got != 42 {
		t.Fatalf("snapshot delay = %d, want 42", got)
	}
}

func TestObserverGetObservationDuringUpdates(t *testing.T) {
	observer := &Observer{status: []*OutboundStatus{{OutboundTag: "proxy", Alive: true}}}

	var updates sync.WaitGroup
	updates.Add(1)
	go func() {
		defer updates.Done()
		for delay := range int64(1000) {
			observer.updateStatusForResult("proxy", &ProbeResult{Alive: true, Delay: delay})
		}
	}()

	for range 1000 {
		report, err := observer.GetObservation(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		statuses := report.(*ObservationResult).Status
		if len(statuses) != 1 || statuses[0] == nil || statuses[0].OutboundTag != "proxy" {
			t.Fatalf("unexpected Observatory snapshot: %+v", statuses)
		}
	}
	updates.Wait()
}

func TestObserverUpdateStatusPrunesStaleOutbounds(t *testing.T) {
	observer := &Observer{
		status: []*OutboundStatus{
			{
				OutboundTag:     "keep",
				Alive:           true,
				Delay:           42,
				LastErrorReason: "",
				LastSeenTime:    111,
				LastTryTime:     222,
			},
			{
				OutboundTag:     "drop",
				Alive:           false,
				Delay:           99999999,
				LastErrorReason: "probe failed",
				LastSeenTime:    333,
				LastTryTime:     444,
			},
		},
	}

	observer.clearRemovedOutbounds([]string{"keep"})

	if len(observer.status) != 1 {
		t.Fatalf("expected 1 status after pruning, got %d", len(observer.status))
	}

	got := observer.status[0]
	if got.OutboundTag != "keep" {
		t.Fatalf("expected remaining status for keep, got %q", got.OutboundTag)
	}
	if !got.Alive {
		t.Fatal("expected remaining status to preserve Alive field")
	}
	if got.Delay != 42 {
		t.Fatalf("expected remaining status to preserve Delay, got %d", got.Delay)
	}
	if got.LastSeenTime != 111 {
		t.Fatalf("expected remaining status to preserve LastSeenTime, got %d", got.LastSeenTime)
	}
	if got.LastTryTime != 222 {
		t.Fatalf("expected remaining status to preserve LastTryTime, got %d", got.LastTryTime)
	}
}

func TestObserverUpdateStatusClearsWhenNoOutboundsRemain(t *testing.T) {
	observer := &Observer{
		status: []*OutboundStatus{
			{OutboundTag: "drop-1"},
			{OutboundTag: "drop-2"},
		},
	}

	observer.clearRemovedOutbounds(nil)

	if len(observer.status) != 0 {
		t.Fatalf("expected all statuses to be removed, got %d", len(observer.status))
	}
}
