//go:build windows
// +build windows

package buf

import (
	"net"
	"testing"
	"time"
)

type readVResult struct {
	mb  MultiBuffer
	err error
}

func TestReadVReaderIdleMultiReadDeadline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	client, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var peer net.Conn
	select {
	case peer = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("timed out accepting local TCP connection")
	}
	defer peer.Close()

	rawConn, err := client.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	reader := NewReadVReader(client, rawConn, nil)
	reader.alloc.current = 2

	// Complete a multi-buffer read first so the next Init must reset the
	// readiness gate before this idle read.
	if _, err := peer.Write([]byte{0x42}); err != nil {
		t.Fatal(err)
	}
	firstRead := make(chan readVResult, 1)
	go func() {
		mb, err := reader.ReadMultiBuffer()
		firstRead <- readVResult{mb: mb, err: err}
	}()

	var first readVResult
	select {
	case first = <-firstRead:
	case <-time.After(2 * time.Second):
		_ = client.Close()
		t.Fatal("initial multi-buffer read did not complete")
	}
	if first.err != nil {
		ReleaseMulti(first.mb)
		t.Fatalf("initial multi-buffer read: %v", first.err)
	}
	if first.mb.Len() == 0 {
		t.Fatal("initial multi-buffer read returned no data")
	}
	ReleaseMulti(first.mb)

	// ReadMultiBuffer adjusts this count based on the first result. Force the
	// second call through the multi-buffer path so it exercises another Init.
	reader.alloc.current = 2
	idleStarted := make(chan struct{})
	idleRead := make(chan error, 1)
	go func() {
		close(idleStarted)
		mb, err := reader.ReadMultiBuffer()
		ReleaseMulti(mb)
		idleRead <- err
	}()
	<-idleStarted
	select {
	case err := <-idleRead:
		t.Fatalf("idle read returned before its deadline: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	if err := client.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-idleRead:
		netErr, ok := err.(net.Error)
		if !ok || !netErr.Timeout() {
			t.Fatalf("idle read error = %v, want a timeout", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("idle read did not return after its deadline")
		// On the old implementation, WSARecv remains blocked despite the Go
		// deadline. Supply data so the test can release that call and exit.
		_, _ = peer.Write([]byte{0x24})
		select {
		case <-idleRead:
		case <-time.After(2 * time.Second):
			t.Fatal("idle read remained blocked after fallback data")
		}
	}
}
