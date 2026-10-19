package hysteria

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestClientDialLockCancellation(t *testing.T) {
	for _, datagram := range []bool{false, true} {
		name := "TCP"
		if datagram {
			name = "UDP"
		}
		t.Run(name, func(t *testing.T) {
			for _, busy := range []bool{false, true} {
				c := &client{lock: make(chan struct{}, 1)}
				if busy {
					c.lock <- struct{}{}
				}
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				var conn stat.Connection
				var err error
				if datagram {
					conn, err = c.udp(ctx)
				} else {
					conn, err = c.tcp(ctx)
				}
				if conn != nil || !errors.Is(err, context.Canceled) {
					t.Fatalf("busy=%v: canceled dial returned (%v, %v)", busy, conn, err)
				}
			}

			c := &client{lock: make(chan struct{}, 1)}
			c.lock <- struct{}{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				if datagram {
					_, err := c.udp(ctx)
					done <- err
				} else {
					_, err := c.tcp(ctx)
					done <- err
				}
			}()
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("waiting dial returned %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("cancellation did not interrupt the client lock wait")
			}
			if len(c.lock) != 1 {
				t.Fatal("canceled waiter released another dial's lock")
			}
		})
	}
}

func newAuthTestClient(t *testing.T, handler http.Handler) (*client, <-chan *quic.Conn) {
	t.Helper()
	certificate, _ := cert.MustGenerate(nil, cert.DNSNames("localhost"))
	certPEM, keyPEM := certificate.ToPEM()
	keyPair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	connections := make(chan *quic.Conn, 1)
	server := &http3.Server{
		TLSConfig:       &tls.Config{Certificates: []tls.Certificate{keyPair}},
		QUICConfig:      &quic.Config{EnableDatagrams: true},
		EnableDatagrams: true,
		Handler:         handler,
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			connections <- conn
			return ctx
		},
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(pc) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = pc.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("auth server did not stop")
		}
	})
	addr := pc.LocalAddr().(*net.UDPAddr)
	c := &client{
		lock:      make(chan struct{}, 1),
		dest:      xnet.UDPDestination(xnet.IPAddress(addr.IP), xnet.Port(addr.Port)),
		config:    &Config{Auth: "test"},
		tlsConfig: &tls.Config{InsecureSkipVerify: true},
	}
	t.Cleanup(func() {
		if c.conn != nil {
			c.close()
		}
	})
	return c, connections
}

func TestClientAuthCancellation(t *testing.T) {
	started := make(chan struct{})
	stopped := make(chan struct{})
	c, _ := newAuthTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(stopped)
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.dial(ctx) }()
	select {
	case <-started:
	case err := <-done:
		t.Fatalf("dial returned before auth request: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("auth request did not reach server")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled auth returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not interrupt authentication")
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not observe authentication cancellation")
	}
	if c.conn != nil || c.tr != nil || c.pktConn != nil {
		t.Fatal("canceled authentication retained connection state")
	}
}

func TestClientAuthConnectionLifecycle(t *testing.T) {
	for _, statusCode := range []int{http.StatusUnauthorized, StatusAuthOK} {
		name := "Rejected"
		if statusCode == StatusAuthOK {
			name = "Accepted"
		}
		t.Run(name, func(t *testing.T) {
			c, connections := newAuthTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(statusCode)
			}))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := c.dial(ctx)
			var serverConn *quic.Conn
			select {
			case serverConn = <-connections:
			case <-ctx.Done():
				t.Fatal("auth connection did not reach server")
			}
			if statusCode != StatusAuthOK {
				if err == nil {
					t.Fatal("rejected authentication succeeded")
				}
				select {
				case <-serverConn.Context().Done():
				case <-ctx.Done():
					t.Fatal("rejected authentication left QUIC connection open")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			conn := c.conn
			if err := c.dial(ctx); err != nil || c.conn != conn {
				t.Fatalf("authenticated connection was not reused: %v", err)
			}
			select {
			case <-conn.Context().Done():
				t.Fatal("successful authentication closed the retained QUIC connection")
			default:
			}
		})
	}
}

func TestClientCleanupReleasesMapLock(t *testing.T) {
	// An unbuffered lock lets the test pause cleanup inside a client without
	// holding the manager lock itself or relying on the cleanup ticker.
	c := &client{lock: make(chan struct{})}
	m := &clientManager{m: map[dialerConf]*client{{}: c}}
	done := make(chan struct{})
	go func() {
		m.cleanInactive()
		close(done)
	}()
	select {
	case <-c.lock:
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup did not reach client")
	}
	locked := make(chan struct{})
	go func() {
		m.Lock()
		m.Unlock()
		close(locked)
	}()
	select {
	case <-locked:
	case <-time.After(5 * time.Second):
		t.Error("client cleanup blocked unrelated client-map writes")
	}
	// Let the client release its lock, allowing cleanup and any blocked writer
	// to finish even if the map-lock assertion above failed.
	c.lock <- struct{}{}
	<-done
	<-locked
}
