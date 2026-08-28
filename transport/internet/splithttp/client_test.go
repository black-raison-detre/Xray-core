package splithttp

import (
	"bytes"
	"errors"
	"io"
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
