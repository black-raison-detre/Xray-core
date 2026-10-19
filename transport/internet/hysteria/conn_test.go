package hysteria

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
)

func TestInterConnCloseUnblocksStalledWrite(t *testing.T) {
	certificate, _ := cert.MustGenerate(nil, cert.DNSNames("localhost"))
	certPEM, keyPEM := certificate.ToPEM()
	keyPair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	serverConfig := &quic.Config{
		InitialStreamReceiveWindow:     1024,
		MaxStreamReceiveWindow:         1024,
		InitialConnectionReceiveWindow: 1024,
		MaxConnectionReceiveWindow:     1024,
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{keyPair},
		NextProtos:   []string{"h3"},
	}, serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	clientConn, err := quic.DialAddr(ctx, listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientConn.CloseWithError(0, "test cleanup") })

	serverConn, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverConn.CloseWithError(0, "test cleanup") })

	transportClient := &client{lock: make(chan struct{}, 1), conn: clientConn}
	connection, err := transportClient.tcp(ctx)
	if err != nil {
		t.Fatal(err)
	}
	streamConn := connection.(*interConn)

	type writeResult struct {
		n   int
		err error
	}
	writeDone := make(chan writeResult, 1)
	go func() {
		payload := make([]byte, 1<<20)
		n, err := streamConn.Write(payload)
		writeDone <- writeResult{n: n, err: err}
	}()

	serverStream, err := serverConn.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := serverStream.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var firstByte [1]byte
	if n, err := serverStream.Read(firstByte[:]); n != 1 || err != nil {
		t.Fatalf("server did not receive the start of the request: read %d bytes, error %v", n, err)
	}

	select {
	case result := <-writeDone:
		t.Fatalf("write completed with %d bytes and error %v despite the exhausted receive window", result.n, result.err)
	case <-time.After(100 * time.Millisecond):
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- streamConn.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close returned an error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked behind the stalled QUIC write")
	}

	select {
	case result := <-writeDone:
		if result.err == nil {
			t.Fatalf("stalled write unexpectedly completed successfully with %d bytes", result.n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not cancel the stalled QUIC write")
	}
}
