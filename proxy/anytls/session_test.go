package anytls

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestClientSettingsUsesCoreVersion(t *testing.T) {
	p := DefaultPaddingFactory()
	m, err := parseSettings(clientSettings(p))
	if err != nil || m["v"] != "2" || m["client"] == "" || m["padding-md5"] != p.MD5() {
		t.Fatalf("bad settings: %#v, %v", m, err)
	}
}

func TestV2NegotiationAndStreamRemainder(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	accepted := make(chan *Stream, 1)
	server := NewServerSession(b, func(st *Stream) { accepted <- st })
	server.padding.Store(DefaultPaddingFactory())
	client := NewSession(a)
	go server.Serve()
	go client.Serve()
	if err := client.StartClient(DefaultPaddingFactory()); err != nil {
		t.Fatal(err)
	}
	st, err := client.NewStream()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write([]byte("abcdef")); err != nil {
		t.Fatal(err)
	}
	select {
	case peer := <-accepted:
		buf := make([]byte, 2)
		if n, err := peer.Read(buf); err != nil || n != 2 || string(buf) != "ab" {
			t.Fatalf("first read = %q, %d, %v", buf[:n], n, err)
		}
		buf = make([]byte, 4)
		if n, err := peer.Read(buf); err != nil || n != 4 || string(buf) != "cdef" {
			t.Fatalf("second read = %q, %d, %v", buf[:n], n, err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not receive stream")
	}
	if !client.WaitV2(time.Second) {
		t.Fatal("v2 negotiation did not finish")
	}
}

func TestV1StreamDoesNotWaitForSYNACK(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	s := NewSession(a)
	if err := s.StartClient(DefaultPaddingFactory()); err != nil {
		t.Fatal(err)
	}
	st, err := s.NewStream()
	if err != nil {
		t.Fatal(err)
	}
	if !st.WaitSYNACK(time.Millisecond) {
		t.Fatal("v1 stream must not wait for SYNACK")
	}
	go func() { _, _ = io.Copy(io.Discard, b) }()
}

func TestWaitSYNACKNegotiatesBeforeAccept(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	s := NewSession(a)
	if err := s.StartClient(DefaultPaddingFactory()); err != nil {
		t.Fatal(err)
	}
	st, err := s.NewStream()
	if err != nil {
		t.Fatal(err)
	}
	s.markV2Negotiated()
	st.ack(nil)
	if err := st.WaitSYNACKError(50 * time.Millisecond); err != nil {
		t.Fatalf("accepted stream failed: %v", err)
	}
}

func TestWaitSYNACKCachesLegacyNegotiation(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	s := NewSession(a)
	if err := s.StartClient(DefaultPaddingFactory()); err != nil {
		t.Fatal(err)
	}
	first, err := s.NewStream()
	if err != nil {
		t.Fatal(err)
	}
	if err := first.WaitSYNACKError(20 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	second, err := s.NewStream()
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := second.WaitSYNACKError(100 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed >= 20*time.Millisecond {
		t.Fatalf("cached legacy negotiation took %v", elapsed)
	}
}

func TestWaitSYNACKReturnsRejection(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	s := NewSession(a)
	if err := s.StartClient(DefaultPaddingFactory()); err != nil {
		t.Fatal(err)
	}
	st, err := s.NewStream()
	if err != nil {
		t.Fatal(err)
	}
	s.markV2Negotiated()
	st.ack([]byte("denied"))
	if err := st.WaitSYNACKError(50 * time.Millisecond); err == nil || err.Error() != "denied" {
		t.Fatalf("rejection = %v", err)
	}
}

func TestWaitSYNACKTimesOutAfterV2Negotiation(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	s := NewSession(a)
	if err := s.StartClient(DefaultPaddingFactory()); err != nil {
		t.Fatal(err)
	}
	st, err := s.NewStream()
	if err != nil {
		t.Fatal(err)
	}
	s.markV2Negotiated()
	if err := st.WaitSYNACKError(20 * time.Millisecond); err == nil || err.Error() != "anytls: SYNACK timeout" {
		t.Fatalf("timeout = %v", err)
	}
}
