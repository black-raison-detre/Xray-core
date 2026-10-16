package splithttp

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
)

type closeTrackingReader struct {
	io.Reader
	closed atomic.Bool
}

func (r *closeTrackingReader) Close() error {
	r.closed.Store(true)
	return nil
}

func TestWaitReadCloserSetUnblocksRead(t *testing.T) {
	w := &WaitReadCloser{Wait: make(chan struct{})}
	started := make(chan struct{})
	type result struct {
		data string
		err  error
	}
	resultCh := make(chan result, 1)
	go func() {
		close(started)
		data, err := io.ReadAll(w)
		resultCh <- result{data: string(data), err: err}
	}()

	<-started
	w.Set(io.NopCloser(bytes.NewBufferString("ready")))
	got := <-resultCh
	if got.err != nil {
		t.Fatal(got.err)
	}
	if got.data != "ready" {
		t.Fatalf("read data = %q, want ready", got.data)
	}
}

func TestWaitReadCloserCloseBeforeSet(t *testing.T) {
	w := &WaitReadCloser{Wait: make(chan struct{})}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Read(make([]byte, 1)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("read error = %v, want io.ErrClosedPipe", err)
	}

	reader := &closeTrackingReader{Reader: bytes.NewBufferString("late")}
	w.Set(reader)
	if !reader.closed.Load() {
		t.Fatal("reader supplied after Close was not closed")
	}
}

func TestWaitReadCloserConcurrentSetReadClose(t *testing.T) {
	for range 100 {
		w := &WaitReadCloser{Wait: make(chan struct{})}
		reader := &closeTrackingReader{Reader: bytes.NewBufferString("ready")}
		start := make(chan struct{})
		var workers sync.WaitGroup
		workers.Add(2)
		go func() {
			defer workers.Done()
			<-start
			w.Set(reader)
		}()
		var data [5]byte
		var n int
		var readErr error
		go func() {
			defer workers.Done()
			<-start
			n, readErr = w.Read(data[:])
		}()
		close(start)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		workers.Wait()
		if readErr != nil && !errors.Is(readErr, io.ErrClosedPipe) {
			t.Fatalf("read error = %v, want data or io.ErrClosedPipe", readErr)
		}
		if readErr == nil && string(data[:n]) != "ready" {
			t.Fatalf("read data = %q, want ready", data[:n])
		}
		if !reader.closed.Load() {
			t.Fatal("reader leaked when Set raced with Close")
		}
	}
}
