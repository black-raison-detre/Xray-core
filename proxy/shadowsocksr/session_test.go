package shadowsocksr

import (
	"bytes"
	"io"
	stdnet "net"
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
