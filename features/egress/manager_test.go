package egress

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestBindingsAndStatusUseTheSameImmutableSnapshot(t *testing.T) {
	manager := &Manager{snapshot: Select(testObservation(), Options{}, true)}
	status := manager.Snapshot()
	ipv4 := manager.BindingForNetwork("tcp4")
	ipv6 := manager.BindingForNetwork("udp6")
	if ipv4 == nil || status.IPv4.Interface == nil || ipv4.Name != status.IPv4.Interface.Name || ipv4.Index != status.IPv4.Interface.Index {
		t.Fatalf("IPv4 binding and status differ: binding=%+v status=%+v", ipv4, status.IPv4.Interface)
	}
	if ipv6 == nil || status.IPv6.Interface == nil || ipv6.Name != status.IPv6.Interface.Name || ipv6.IPv6Index != status.IPv6.Interface.IPv6Index {
		t.Fatalf("IPv6 binding and status differ: binding=%+v status=%+v", ipv6, status.IPv6.Interface)
	}
	if ipv4.Name == ipv6.Name {
		t.Fatal("test observation must exercise independent family selection")
	}

	ipv4.Name = "changed by caller"
	status.IPv6.Interface.Addresses[0] = "changed by caller"
	next := manager.Snapshot()
	if next.IPv4.Interface.Name == ipv4.Name || next.IPv6.Interface.Addresses[0] == "changed by caller" {
		t.Fatalf("caller mutated the published snapshot: %+v", next)
	}
}

func TestClosedManagerIsDistinctFromActiveUnavailableSelection(t *testing.T) {
	manager := &Manager{snapshot: Select(Observation{IPv4Supported: true, IPv6Supported: true}, Options{}, true)}
	if manager.Closed() {
		t.Fatal("active manager with unavailable routes was treated as closed")
	}
	if manager.BindingForNetwork("tcp4") != nil {
		t.Fatal("active manager with no route exposed a binding")
	}
	manager.snapshot = &Snapshot{State: "inactive"}
	if !manager.Closed() {
		t.Fatal("cleared manager was not marked closed")
	}
}

func TestNetworkChangeDebounceCapsSustainedNotifications(t *testing.T) {
	stop := make(chan struct{})
	stopGuard := time.AfterFunc(3*refreshMaxDebounce, func() { close(stop) })
	defer stopGuard.Stop()
	refresh := make(chan struct{}, 1)
	force := make(chan chan struct{}, 1)
	fallback := make(chan time.Time, 1)
	forceCompleted := make(chan struct{})
	force <- forceCompleted
	fallback <- time.Now()

	stormDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stormDone:
				return
			case <-ticker.C:
				select {
				case refresh <- struct{}{}:
				default:
				}
			}
		}
	}()

	refreshes := 0
	started := time.Now()
	completed := waitForNetworkChanges(stop, refresh, force, fallback, func() { refreshes++ })
	elapsed := time.Since(started)
	close(stormDone)
	if !completed {
		t.Fatal("network watcher did not finish debouncing under sustained notifications")
	}
	if elapsed > refreshMaxDebounce+500*time.Millisecond {
		t.Fatalf("sustained notifications delayed refresh for %s", elapsed)
	}
	if refreshes < 2 {
		t.Fatalf("forced and fallback refreshes serviced %d times; want both", refreshes)
	}
	select {
	case <-forceCompleted:
	default:
		t.Fatal("forced refresh was not completed during debounce")
	}
}

func TestRefreshBoundsTimeSpentEnqueueingForcedRequest(t *testing.T) {
	manager := &Manager{
		force: make(chan chan struct{}, 1),
		stop:  make(chan struct{}),
	}
	manager.force <- make(chan struct{})
	started := time.Now()
	manager.refreshWithTimeout(context.Background(), 30*time.Millisecond)
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Fatalf("refresh blocked %s on a full force queue", elapsed)
	}
}

func TestConcurrentRefreshCallersRespectContextWhileForceQueueIsFull(t *testing.T) {
	manager := &Manager{
		force: make(chan chan struct{}, 1),
		stop:  make(chan struct{}),
	}
	manager.force <- make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	const callers = 8
	var wait sync.WaitGroup
	wait.Add(callers)
	for range callers {
		go func() {
			defer wait.Done()
			manager.Refresh(ctx)
		}()
	}
	done := make(chan struct{})
	go func() {
		wait.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("concurrent forced refresh callers outlived their request context")
	}
}
