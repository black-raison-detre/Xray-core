package anytls

import (
	"context"
	"encoding/binary"
	"io"
	stdnet "net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type clientManagerTestDialer struct {
	calls atomic.Int32
}

func (d *clientManagerTestDialer) Dial(context.Context, xnet.Destination) (stat.Connection, error) {
	d.calls.Add(1)
	client, server := stdnet.Pipe()
	go serveClientManagerTestPeer(server)
	return client, nil
}

func (*clientManagerTestDialer) DestIpAddress() stdnet.IP                              { return nil }
func (*clientManagerTestDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

func readClientManagerTestAuthPreface(conn io.Reader) error {
	var header [AuthPrefaceSize + 2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	paddingLength := int(binary.BigEndian.Uint16(header[AuthPrefaceSize:]))
	_, err := io.CopyN(io.Discard, conn, int64(paddingLength))
	return err
}

func serveClientManagerTestPeer(conn stdnet.Conn) {
	if err := readClientManagerTestAuthPreface(conn); err != nil {
		_ = conn.Close()
		return
	}
	_ = NewServerSession(conn, nil).Serve()
}

type clientManagerContextDialer struct {
	calls    atomic.Int32
	contexts chan context.Context
	peers    chan stdnet.Conn
}

func (d *clientManagerContextDialer) Dial(ctx context.Context, _ xnet.Destination) (stat.Connection, error) {
	d.calls.Add(1)
	client, peer := stdnet.Pipe()
	d.contexts <- ctx
	go func() {
		<-ctx.Done()
		_ = client.Close()
	}()
	go func() {
		if err := readClientManagerTestAuthPreface(peer); err != nil {
			_ = peer.Close()
			return
		}
		d.peers <- peer
		_ = NewServerSession(peer, nil).Serve()
	}()
	return client, nil
}

func (*clientManagerContextDialer) DestIpAddress() stdnet.IP                              { return nil }
func (*clientManagerContextDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

func newClientManagerTestManager(t *testing.T, disableReuse bool, minIdle uint32, dialer internet.Dialer) *clientSessionManager {
	t.Helper()
	client := &Client{
		server: protocol.NewServerSpec(
			xnet.TCPDestination(xnet.DomainAddress("example.com"), 443),
			&protocol.MemoryUser{Account: NewMemoryAccount("client-manager-test")},
		),
		padding:      DefaultPaddingFactory(),
		disableReuse: disableReuse,
	}
	manager := &clientSessionManager{c: client}
	manager.configure(time.Hour, time.Hour, minIdle, client.padding)
	t.Cleanup(func() { _ = manager.close() })
	return manager
}

func TestClientSessionManagerUsesSeparateSessionsForConcurrentStreams(t *testing.T) {
	dialer := &clientManagerTestDialer{}
	manager := newClientManagerTestManager(t, false, 0, dialer)

	start := make(chan struct{})
	streams := make(chan *Stream, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			stream, err := manager.openStream(context.Background(), dialer)
			if err != nil {
				errs <- err
				return
			}
			streams <- stream
		}()
	}
	close(start)
	wg.Wait()
	close(streams)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	var opened []*Stream
	for stream := range streams {
		opened = append(opened, stream)
	}
	if len(opened) != 2 {
		t.Fatalf("opened %d streams, want 2", len(opened))
	}
	if opened[0].s == opened[1].s {
		t.Fatal("simultaneous streams shared one session")
	}
	if got := dialer.calls.Load(); got != 2 {
		t.Fatalf("dial calls = %d, want 2", got)
	}
	for _, stream := range opened {
		_ = stream.Close()
	}
}

func TestClientSessionManagerReusesSessionAfterStreamCloses(t *testing.T) {
	dialer := &clientManagerTestDialer{}
	manager := newClientManagerTestManager(t, false, 0, dialer)

	first, err := manager.openStream(context.Background(), dialer)
	if err != nil {
		t.Fatal(err)
	}
	session := first.s
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := manager.openStream(context.Background(), dialer)
	if err != nil {
		t.Fatal(err)
	}
	if second.s != session {
		t.Fatal("idle session was not reused")
	}
	if got := dialer.calls.Load(); got != 1 {
		t.Fatalf("dial calls = %d, want 1", got)
	}
	_ = second.Close()
}

type clientManagerContextKey struct{}

func TestClientSessionManagerKeepsDialContextUntilSessionCloses(t *testing.T) {
	dialer := &clientManagerContextDialer{
		contexts: make(chan context.Context, 2),
		peers:    make(chan stdnet.Conn, 2),
	}
	manager := newClientManagerTestManager(t, false, 0, dialer)
	callerCtx, cancelCaller := context.WithCancel(context.WithValue(context.Background(), clientManagerContextKey{}, "kept"))
	first, err := manager.openStream(callerCtx, dialer)
	if err != nil {
		t.Fatal(err)
	}
	dialCtx := <-dialer.contexts
	if got := dialCtx.Value(clientManagerContextKey{}); got != "kept" {
		t.Fatalf("dial context value = %v, want kept", got)
	}
	_ = <-dialer.peers

	cancelCaller()
	select {
	case <-dialCtx.Done():
		t.Fatal("per-stream caller cancellation ended the reusable session context")
	default:
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := manager.openStream(context.Background(), dialer)
	if err != nil {
		t.Fatal(err)
	}
	if second.s != first.s {
		t.Fatal("session was not reusable after its initial caller context was canceled")
	}
	if got := dialer.calls.Load(); got != 1 {
		t.Fatalf("dial calls = %d, want 1", got)
	}
	_ = second.Close()

	if err := manager.close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dialCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("manager shutdown did not cancel the session transport context")
	}
}

func TestClientSessionManagerRemoteCloseCancelsSessionContext(t *testing.T) {
	dialer := &clientManagerContextDialer{
		contexts: make(chan context.Context, 1),
		peers:    make(chan stdnet.Conn, 1),
	}
	manager := newClientManagerTestManager(t, false, 0, dialer)
	stream, err := manager.openStream(context.Background(), dialer)
	if err != nil {
		t.Fatal(err)
	}
	dialCtx := <-dialer.contexts
	peer := <-dialer.peers
	_ = peer.Close()
	select {
	case <-dialCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("remote session failure did not cancel the session transport context")
	}
	if !stream.s.closed.Load() {
		t.Fatal("remote close did not close the session")
	}
}

type clientManagerCanceledDialer struct {
	started  chan struct{}
	contexts chan context.Context
}

func (d *clientManagerCanceledDialer) Dial(ctx context.Context, _ xnet.Destination) (stat.Connection, error) {
	d.contexts <- ctx
	close(d.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

func (*clientManagerCanceledDialer) DestIpAddress() stdnet.IP                              { return nil }
func (*clientManagerCanceledDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

func TestClientSessionManagerCallerCancellationDuringDial(t *testing.T) {
	dialer := &clientManagerCanceledDialer{
		started:  make(chan struct{}),
		contexts: make(chan context.Context, 1),
	}
	manager := newClientManagerTestManager(t, false, 0, dialer)
	callerCtx, cancelCaller := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := manager.openStream(callerCtx, dialer)
		result <- err
	}()
	<-dialer.started
	dialCtx := <-dialer.contexts
	cancelCaller()
	select {
	case err := <-result:
		if err != context.Canceled {
			t.Fatalf("openStream error = %v, want %v", err, context.Canceled)
		}
	case <-time.After(time.Second):
		t.Fatal("caller cancellation did not stop the in-flight dial")
	}
	if err := manager.shutdownCtx.Err(); err != nil {
		t.Fatalf("caller cancellation canceled the manager lifetime context: %v", err)
	}
	if err := dialCtx.Err(); err != context.Canceled {
		t.Fatalf("dial context error = %v, want %v", err, context.Canceled)
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.sessions) != 0 || len(manager.pending) != 0 {
		t.Fatalf("failed dial left tracked state: sessions=%d pending=%d", len(manager.sessions), len(manager.pending))
	}
}

func TestClientSessionManagerDisableReuseClosesSession(t *testing.T) {
	dialer := &clientManagerTestDialer{}
	manager := newClientManagerTestManager(t, true, 0, dialer)
	stream, err := manager.openStream(context.Background(), dialer)
	if err != nil {
		t.Fatal(err)
	}
	session := stream.s
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if !session.closed.Load() {
		t.Fatal("session remained open after its stream closed with reuse disabled")
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if got := len(manager.sessions); got != 0 {
		t.Fatalf("tracked sessions = %d, want 0", got)
	}
}

func TestClientSessionManagerMinIdleZeroExpiresAllIdleSessions(t *testing.T) {
	dialer := &clientManagerTestDialer{}
	manager := newClientManagerTestManager(t, false, 0, dialer)
	stream, err := manager.openStream(context.Background(), dialer)
	if err != nil {
		t.Fatal(err)
	}
	session := stream.s
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	manager.reap(time.Now().Add(2 * time.Hour))
	if !session.closed.Load() {
		t.Fatal("idle session was retained despite minIdleSession being zero")
	}
}

type clientManagerBlockedDialer struct {
	started     chan struct{}
	allowReturn chan struct{}
	canceled    chan struct{}
	conn        stdnet.Conn
	once        sync.Once
}

func (d *clientManagerBlockedDialer) Dial(ctx context.Context, _ xnet.Destination) (stat.Connection, error) {
	d.once.Do(func() { close(d.started) })
	go func() {
		<-ctx.Done()
		close(d.canceled)
	}()
	<-d.allowReturn // Deliberately return a connection after cancellation to test publication.
	return d.conn, nil
}

func (*clientManagerBlockedDialer) DestIpAddress() stdnet.IP                              { return nil }
func (*clientManagerBlockedDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

func TestClientSessionManagerCloseDuringDialDoesNotPublishSession(t *testing.T) {
	clientConn, peerConn := stdnet.Pipe()
	dialer := &clientManagerBlockedDialer{
		started:     make(chan struct{}),
		allowReturn: make(chan struct{}),
		canceled:    make(chan struct{}),
		conn:        clientConn,
	}
	manager := newClientManagerTestManager(t, false, 0, dialer)
	result := make(chan error, 1)
	go func() {
		_, err := manager.openStream(context.Background(), dialer)
		result <- err
	}()
	<-dialer.started
	if err := manager.close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dialer.canceled:
	case <-time.After(time.Second):
		t.Fatal("manager shutdown did not cancel the in-flight dial context")
	}
	close(dialer.allowReturn)
	select {
	case err := <-result:
		if err != ErrSessionClosed {
			t.Fatalf("openStream error = %v, want %v", err, ErrSessionClosed)
		}
	case <-time.After(time.Second):
		t.Fatal("openStream did not finish after the dial returned")
	}
	_ = peerConn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peerConn.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection returned after shutdown was not closed")
	}
	_ = peerConn.Close()
}
