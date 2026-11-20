package anytls

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

const regressionWait = time.Second

func TestUpstreamRegressionTrailingPSHIsReadBeforeFIN(t *testing.T) {
	const (
		streamID  uint32 = 41
		frameSize        = 1024
		frames           = 32
	)

	payload := make([]byte, frameSize*frames)
	for i := range payload {
		payload[i] = byte(i*31 + 7)
	}
	var wire bytes.Buffer
	for off := 0; off < len(payload); off += frameSize {
		if err := (Frame{Command: CommandPSH, SessionID: streamID, Data: payload[off : off+frameSize]}).WriteTo(&wire); err != nil {
			t.Fatal(err)
		}
	}
	if err := (Frame{Command: CommandFIN, SessionID: streamID}).WriteTo(&wire); err != nil {
		t.Fatal(err)
	}

	rw := &regressionReader{r: bytes.NewReader(wire.Bytes())}
	s := NewSession(rw)
	st := newStream(s, streamID)
	s.streams.Store(streamID, st)
	if err := st.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- s.Serve() }()

	got := make([]byte, 0, len(payload))
	buf := make([]byte, frameSize)
	for {
		n, err := st.Read(buf)
		got = append(got, buf[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read stream: %v", err)
		}
		if n == 0 {
			t.Fatal("stream read returned no data and no error")
		}
		// Let Serve run ahead so FIN arrives while there is still unread PSH.
		time.Sleep(time.Millisecond)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("read %d bytes before EOF, want %d", len(got), len(payload))
	}
	select {
	case <-serveDone:
	case <-time.After(regressionWait):
		t.Fatal("Serve did not finish after FIN")
	}
}

func TestUpstreamRegressionSimultaneousFINKeepsSessionUsable(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	_ = clientConn.SetDeadline(deadline)
	_ = serverConn.SetDeadline(deadline)
	client := NewSession(clientConn)
	accepted := make(chan *Stream, 4)
	server := NewServerSession(serverConn, func(st *Stream) { accepted <- st })
	clientServeDone := make(chan error, 1)
	serverServeDone := make(chan error, 1)
	go func() { clientServeDone <- client.Serve() }()
	go func() { serverServeDone <- server.Serve() }()
	defer func() {
		_ = client.Close()
		_ = server.Close()
	}()

	if err := client.StartClient(DefaultPaddingFactory()); err != nil {
		t.Fatal(err)
	}
	first, err := client.NewStream()
	if err != nil {
		t.Fatal(err)
	}
	firstWriteDone := make(chan error, 1)
	go func() {
		_, writeErr := first.Write([]byte("before simultaneous FIN"))
		firstWriteDone <- writeErr
	}()
	peer := waitRegressionStream(t, accepted)
	firstPayload := make([]byte, len("before simultaneous FIN"))
	if _, err := io.ReadFull(peer, firstPayload); err != nil || string(firstPayload) != "before simultaneous FIN" {
		t.Fatalf("initial stream payload = %q, %v", firstPayload, err)
	}
	waitRegressionWrite(t, firstWriteDone)

	closeResults := make(chan error, 2)
	go func() { closeResults <- first.Close() }()
	go func() { closeResults <- peer.Close() }()
	for i := 0; i < 2; i++ {
		select {
		case err := <-closeResults:
			if err != nil {
				t.Fatalf("simultaneous stream close: %v", err)
			}
		case <-time.After(regressionWait):
			t.Fatal("simultaneous FIN writes did not finish")
		}
	}

	second, err := client.NewStream()
	if err != nil {
		t.Fatalf("create stream after simultaneous FIN: %v", err)
	}
	secondWriteDone := make(chan error, 1)
	go func() {
		_, writeErr := second.Write([]byte("session still works"))
		secondWriteDone <- writeErr
	}()
	peer = waitRegressionStream(t, accepted)
	secondPayload := make([]byte, len("session still works"))
	if _, err := io.ReadFull(peer, secondPayload); err != nil || string(secondPayload) != "session still works" {
		t.Fatalf("post-FIN stream payload = %q, %v", secondPayload, err)
	}
	waitRegressionWrite(t, secondWriteDone)
	_ = peer.Close()
	_ = second.Close()
	_ = client.Close()
	_ = server.Close()
	for name, done := range map[string]<-chan error{"client": clientServeDone, "server": serverServeDone} {
		select {
		case <-done:
		case <-time.After(regressionWait):
			t.Fatalf("%s Serve did not stop after session close", name)
		}
	}
}

func TestUpstreamRegressionSessionCloseUnblocksStreamAndReentrantCallback(t *testing.T) {
	clientConn, peerConn := net.Pipe()
	conn := &regressionNotifyingConn{Conn: clientConn, writeStarted: make(chan struct{})}
	s := NewSession(conn)
	if err := s.StartClient(DefaultPaddingFactory()); err != nil {
		t.Fatal(err)
	}
	callbackDone := make(chan struct{})
	var st *Stream
	var err error
	st, err = s.newStreamWithClose(func() {
		_ = st.Close() // Re-enter Close while Session.Close is cleaning up this stream.
		close(callbackDone)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer peerConn.Close()

	readDone := make(chan error, 1)
	go func() {
		_, readErr := st.Read(make([]byte, 1))
		readDone <- readErr
	}()
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := st.Write([]byte("blocked until Session.Close"))
		writeDone <- writeErr
	}()
	select {
	case <-conn.writeStarted:
	case <-time.After(regressionWait):
		t.Fatal("stream writer did not block on transport")
	}

	if err := s.Close(); err != nil {
		t.Fatalf("close session: %v", err)
	}
	select {
	case err := <-readDone:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("blocked stream read = %v, want EOF", err)
		}
	case <-time.After(regressionWait):
		t.Fatal("Session.Close did not release blocked stream reader")
	}
	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("blocked stream writer unexpectedly succeeded")
		}
	case <-time.After(regressionWait):
		t.Fatal("Session.Close did not release blocked transport writer")
	}
	select {
	case <-callbackDone:
	case <-time.After(regressionWait):
		t.Fatal("reentrant stream close callback deadlocked")
	}
}

func TestUpstreamRegressionControlDeadlineInterruptsBusyDataWriter(t *testing.T) {
	conn := newRegressionDeadlineConn()
	s := NewSession(conn)
	if err := s.StartClient(DefaultPaddingFactory()); err != nil {
		t.Fatal(err)
	}
	st, err := s.NewStream()
	if err != nil {
		t.Fatal(err)
	}
	dataWriteDone := make(chan error, 1)
	go func() {
		_, writeErr := st.Write([]byte("busy data writer"))
		dataWriteDone <- writeErr
	}()
	select {
	case <-conn.writeStarted:
	case <-time.After(regressionWait):
		t.Fatal("data writer did not enter the transport")
	}

	controlDone := make(chan error, 1)
	go func() { controlDone <- s.write(Frame{Command: CommandHeartRequest}) }()
	select {
	case <-conn.controlDeadlineSet:
	case <-time.After(regressionWait):
		t.Fatal("control write did not set its deadline")
	}
	select {
	case err := <-dataWriteDone:
		if err == nil {
			t.Fatal("busy data write unexpectedly succeeded")
		}
	case <-time.After(regressionWait):
		t.Fatal("control deadline did not interrupt the busy data writer")
	}
	select {
	case <-controlDone:
	case <-time.After(regressionWait):
		t.Fatal("control write remained blocked behind the data writer")
	}
	if !s.closed.Load() {
		t.Fatal("session was not closed after the timed-out transport write")
	}
}

func TestUpstreamRegressionFirstPaddingGroupContainsSettingsSYNAndPSH(t *testing.T) {
	p, err := NewPaddingFactory([]byte("stop=2\n1=2048-2048"))
	if err != nil {
		t.Fatal(err)
	}
	rw := &regressionBufferConn{}
	s := NewSession(rw)
	if err := s.StartClient(p); err != nil {
		t.Fatal(err)
	}
	st, err := s.NewStream()
	if err != nil {
		t.Fatal(err)
	}
	if n, err := st.Write([]byte("first payload")); err != nil || n != len("first payload") {
		t.Fatalf("first stream write = %d, %v", n, err)
	}

	wire := bytes.NewReader(rw.Bytes())
	settings, err := ReadFrame(wire)
	if err != nil || settings.Command != CommandSettings {
		t.Fatalf("first padded frame = %#v, %v", settings, err)
	}
	syn, err := ReadFrame(wire)
	if err != nil || syn.Command != CommandSYN || syn.SessionID != st.ID() {
		t.Fatalf("second padded frame = %#v, %v", syn, err)
	}
	psh, err := ReadFrame(wire)
	if err != nil || psh.Command != CommandPSH || psh.SessionID != st.ID() || string(psh.Data) != "first payload" {
		t.Fatalf("third padded frame = %#v, %v", psh, err)
	}
	waste, err := ReadFrame(wire)
	if err != nil || waste.Command != CommandWaste || waste.SessionID != 0 {
		t.Fatalf("padding frame = %#v, %v", waste, err)
	}
	if wire.Len() != 0 {
		t.Fatalf("first padding group left %d unparsed bytes", wire.Len())
	}
	if got := rw.Len(); got != 2048 {
		t.Fatalf("first shaped write length = %d, want 2048", got)
	}
}

type regressionReader struct {
	r io.Reader
}

func (c *regressionReader) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *regressionReader) Write(p []byte) (int, error) { return len(p), nil }
func (c *regressionReader) Close() error                { return nil }

type regressionBufferConn struct {
	bytes.Buffer
}

func (c *regressionBufferConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *regressionBufferConn) Close() error             { return nil }

func waitRegressionStream(t *testing.T, streams <-chan *Stream) *Stream {
	t.Helper()
	select {
	case st := <-streams:
		return st
	case <-time.After(regressionWait):
		t.Fatal("server did not accept the stream")
		return nil
	}
}

func waitRegressionWrite(t *testing.T, result <-chan error) {
	t.Helper()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("stream write: %v", err)
		}
	case <-time.After(regressionWait):
		t.Fatal("stream write did not finish after the peer read")
	}
}

type regressionNotifyingConn struct {
	net.Conn
	writeStarted chan struct{}
	writeOnce    sync.Once
}

func (c *regressionNotifyingConn) Write(p []byte) (int, error) {
	c.writeOnce.Do(func() { close(c.writeStarted) })
	return c.Conn.Write(p)
}

type regressionDeadlineConn struct {
	mu                 sync.Mutex
	writeDeadline      time.Time
	deadlineChanged    chan struct{}
	controlDeadlineSet chan struct{}
	writeStarted       chan struct{}
	closed             chan struct{}
	startOnce          sync.Once
	deadlineOnce       sync.Once
	closeOnce          sync.Once
}

func newRegressionDeadlineConn() *regressionDeadlineConn {
	return &regressionDeadlineConn{
		deadlineChanged:    make(chan struct{}, 1),
		controlDeadlineSet: make(chan struct{}),
		writeStarted:       make(chan struct{}),
		closed:             make(chan struct{}),
	}
}

func (c *regressionDeadlineConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *regressionDeadlineConn) Write([]byte) (int, error) {
	c.startOnce.Do(func() { close(c.writeStarted) })
	for {
		c.mu.Lock()
		deadline := c.writeDeadline
		c.mu.Unlock()
		if deadline.IsZero() {
			select {
			case <-c.closed:
				return 0, net.ErrClosed
			case <-c.deadlineChanged:
				continue
			}
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(remaining)
		select {
		case <-c.closed:
			timer.Stop()
			return 0, net.ErrClosed
		case <-c.deadlineChanged:
			timer.Stop()
		case <-timer.C:
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (c *regressionDeadlineConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *regressionDeadlineConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	if deadline.IsZero() {
		c.writeDeadline = time.Time{}
	} else {
		// Compress the production timeout so this regression stays quick.
		c.writeDeadline = time.Now().Add(25 * time.Millisecond)
		c.deadlineOnce.Do(func() { close(c.controlDeadlineSet) })
	}
	c.mu.Unlock()
	select {
	case c.deadlineChanged <- struct{}{}:
	default:
	}
	return nil
}

func (c *regressionDeadlineConn) SetDeadline(deadline time.Time) error {
	if deadline.IsZero() {
		return c.SetWriteDeadline(time.Time{})
	}
	c.mu.Lock()
	c.writeDeadline = deadline
	c.mu.Unlock()
	select {
	case c.deadlineChanged <- struct{}{}:
	default:
	}
	return nil
}

func (c *regressionDeadlineConn) SetReadDeadline(time.Time) error { return nil }
