package shadowsocksr

import (
	"bytes"
	"io"
	stdnet "net"
	"sync"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/shadowsocks/legacy"
	ssrprotocol "github.com/xtls/xray-core/proxy/shadowsocksr/internal/protocol"
	"github.com/xtls/xray-core/proxy/shadowsocksr/internal/ssr"
)

type memoryConn struct {
	read    *bytes.Reader
	written bytes.Buffer
}

func (c *memoryConn) Read(p []byte) (int, error)     { return c.read.Read(p) }
func (c *memoryConn) Write(p []byte) (int, error)    { return c.written.Write(p) }
func (*memoryConn) Close() error                     { return nil }
func (*memoryConn) LocalAddr() stdnet.Addr           { return dummyAddr("local") }
func (*memoryConn) RemoteAddr() stdnet.Addr          { return dummyAddr("remote") }
func (*memoryConn) SetDeadline(time.Time) error      { return nil }
func (*memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (*memoryConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr string

func (d dummyAddr) Network() string { return string(d) }
func (d dummyAddr) String() string  { return string(d) }

func TestOriginPlainSessionLazyHeaderAndResponse(t *testing.T) {
	cipherCore, err := legacy.New("aes-256-cfb", "secret")
	if err != nil {
		t.Fatal(err)
	}
	account := &MemoryAccount{Cipher: cipherCore, Password: "secret", Method: "aes-256-cfb", Protocol: "origin", Obfs: "plain"}
	serverIV := bytes.Repeat([]byte{0x77}, cipherCore.Method().IVSize)
	serverStream, err := cipherCore.NewEncrypter(serverIV)
	if err != nil {
		t.Fatal(err)
	}
	response := []byte("server response split across reads")
	encrypted := make([]byte, len(response))
	serverStream.XORKeyStream(encrypted, response)
	raw := &memoryConn{read: bytes.NewReader(append(serverIV, encrypted...))}
	server := xnet.TCPDestination(xnet.DomainAddress("ssr.example"), 443)
	target := xnet.TCPDestination(xnet.DomainAddress("target.example"), 80)
	session, err := newSessionConn(raw, account, server, target, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if raw.written.Len() != 0 {
		t.Fatal("session wrote before first payload")
	}
	if _, err = session.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	wire := raw.written.Bytes()
	ivLen := cipherCore.Method().IVSize
	if len(wire) <= ivLen {
		t.Fatal("missing encrypted request")
	}
	clientStream, err := cipherCore.NewDecrypter(wire[:ivLen])
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, len(wire)-ivLen)
	clientStream.XORKeyStream(plain, wire[ivLen:])
	header, _ := encodeAddress(target)
	if !bytes.Equal(plain, append(header, []byte("request")...)) {
		t.Fatalf("unexpected request plaintext %x", plain)
	}
	got, err := io.ReadAll(session)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, response) {
		t.Fatalf("response %q", got)
	}
}

func TestUDPCodecPreservesDestination(t *testing.T) {
	cipherCore, _ := legacy.New("chacha20-ietf", "secret")
	account := &MemoryAccount{Cipher: cipherCore, Method: "chacha20-ietf", Protocol: "origin", Obfs: "plain"}
	p := ssrprotocol.NewProtocol("origin")
	key := cipherCore.Key()
	p.SetServerInfo(&ssr.ServerInfo{Key: key, KeyLen: len(key)})
	codec := &udpCodec{account: account, protocol: p}
	dest := xnet.UDPDestination(xnet.DomainAddress("dns.example"), 53)
	packet, err := codec.encode(dest, []byte("query"))
	if err != nil {
		t.Fatal(err)
	}
	gotDest, payload, err := codec.decode(packet)
	if err != nil {
		t.Fatal(err)
	}
	if gotDest.String() != dest.String() || string(payload) != "query" {
		t.Fatalf("got %v %q", gotDest, payload)
	}
}

type sessionBufferProtocol struct {
	buffer     bytes.Buffer
	prepared   chan []byte
	release    chan struct{}
	postCalled chan struct{}
	postOnce   sync.Once
}

func (p *sessionBufferProtocol) SetServerInfo(*ssr.ServerInfo)  {}
func (p *sessionBufferProtocol) GetServerInfo() *ssr.ServerInfo { return &ssr.ServerInfo{} }
func (p *sessionBufferProtocol) SetData(interface{})            {}
func (p *sessionBufferProtocol) GetData() interface{}           { return nil }
func (p *sessionBufferProtocol) GetOverhead() int               { return 0 }

func (p *sessionBufferProtocol) PreEncrypt(data []byte) ([]byte, error) {
	p.buffer.Reset()
	_, _ = p.buffer.Write(data)
	p.prepared <- append([]byte(nil), p.buffer.Bytes()...)
	<-p.release
	return p.buffer.Bytes(), nil
}

func (p *sessionBufferProtocol) PostDecrypt(data []byte) ([]byte, int, error) {
	p.buffer.Reset()
	_, _ = p.buffer.Write([]byte("reply"))
	p.postOnce.Do(func() { close(p.postCalled) })
	return p.buffer.Bytes(), len(data), nil
}

type sessionIdentityStream struct{}

func (sessionIdentityStream) XORKeyStream(dst, src []byte) { copy(dst, src) }

type sessionBarrierConn struct {
	*memoryConn
	readReturned chan struct{}
	writeStarted chan struct{}
	allowWrite   chan struct{}
	readOnce     sync.Once
	writeOnce    sync.Once
}

func (c *sessionBarrierConn) Read(p []byte) (int, error) {
	n, err := c.memoryConn.Read(p)
	c.readOnce.Do(func() { close(c.readReturned) })
	return n, err
}

func (c *sessionBarrierConn) Write(p []byte) (int, error) {
	c.writeOnce.Do(func() { close(c.writeStarted) })
	<-c.allowWrite
	return c.memoryConn.Write(p)
}

func TestSessionConnSerializesFullDuplexProtocolBufferAccess(t *testing.T) {
	cipherCore, err := legacy.New("chacha20-ietf", "secret")
	if err != nil {
		t.Fatal(err)
	}
	account := &MemoryAccount{Cipher: cipherCore, Password: "secret", Method: "chacha20-ietf", Protocol: "origin", Obfs: "plain"}
	raw := &sessionBarrierConn{
		memoryConn:   &memoryConn{read: bytes.NewReader([]byte("server response"))},
		readReturned: make(chan struct{}), writeStarted: make(chan struct{}), allowWrite: make(chan struct{}),
	}
	server := xnet.TCPDestination(xnet.DomainAddress("ssr.example"), 8388)
	target := xnet.TCPDestination(xnet.DomainAddress("target.example"), 80)
	session, err := newSessionConn(raw, account, server, target, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	session.decryptor = sessionIdentityStream{}
	protocol := &sessionBufferProtocol{
		prepared: make(chan []byte, 1), release: make(chan struct{}), postCalled: make(chan struct{}),
	}
	session.protocol = protocol
	var releaseProtocolOnce, releaseNetworkOnce sync.Once
	releaseProtocol := func() { releaseProtocolOnce.Do(func() { close(protocol.release) }) }
	releaseNetwork := func() { releaseNetworkOnce.Do(func() { close(raw.allowWrite) }) }
	defer func() {
		releaseProtocol()
		releaseNetwork()
	}()

	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := session.Write([]byte("outbound request"))
		writeDone <- writeErr
	}()
	expectedFrame := <-protocol.prepared
	readDone := make(chan struct {
		data []byte
		err  error
	}, 1)
	go func() {
		data := make([]byte, 128)
		n, readErr := session.Read(data)
		readDone <- struct {
			data []byte
			err  error
		}{append([]byte(nil), data[:n]...), readErr}
	}()
	select {
	case <-raw.readReturned:
	case <-time.After(time.Second):
		releaseProtocol()
		t.Fatal("reader did not receive the simulated server response")
	}

	postBeforeWriteRelease := false
	select {
	case <-protocol.postCalled:
		postBeforeWriteRelease = true
	case <-time.After(50 * time.Millisecond):
	}
	releaseProtocol()
	select {
	case <-raw.writeStarted:
	case <-time.After(time.Second):
		releaseNetwork()
		t.Fatal("writer did not reach the simulated network write")
	}
	select {
	case <-protocol.postCalled:
	case <-time.After(time.Second):
		releaseNetwork()
		t.Fatal("reader remained blocked during the simulated network write")
	}
	releaseNetwork()
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	readResult := <-readDone
	if readResult.err != nil || !bytes.Equal(readResult.data, []byte("reply")) {
		t.Fatalf("decoded response=%q err=%v", readResult.data, readResult.err)
	}
	if postBeforeWriteRelease {
		t.Fatal("read-side protocol call ran before the write-side frame was copied")
	}

	wire := raw.written.Bytes()
	ivLength := account.Cipher.Method().IVSize
	if len(wire) <= ivLength {
		t.Fatalf("wire output has no encrypted protocol frame: %x", wire)
	}
	stream, err := account.Cipher.NewDecrypter(wire[:ivLength])
	if err != nil {
		t.Fatal(err)
	}
	gotFrame := make([]byte, len(wire)-ivLength)
	stream.XORKeyStream(gotFrame, wire[ivLength:])
	if !bytes.Equal(gotFrame, expectedFrame) {
		t.Fatalf("outbound frame changed during full-duplex protocol access: got %x, want %x", gotFrame, expectedFrame)
	}
}
