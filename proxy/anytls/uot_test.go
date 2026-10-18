package anytls

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/common/net"
)

func TestUoTConnectedGoldenWire(t *testing.T) {
	var b bytes.Buffer
	c := NewUoTCodec(&b, &b)
	d := net.UDPDestination(net.DomainAddress("example.com"), 53)
	if err := c.WriteRequest(true, d); err != nil {
		t.Fatal(err)
	}
	if err := c.WriteConnected([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	want := append([]byte{1, 3, 11}, []byte("example.com")...)
	want = append(want, 0, 53, 0, 2, 'h', 'i')
	if !bytes.Equal(b.Bytes(), want) {
		t.Fatalf("wire %x", b.Bytes())
	}
	connected, got, err := c.ReadRequest()
	if err != nil || !connected || got.Address.String() != "example.com" || got.Port != 53 {
		t.Fatalf("request %#v %v %v", connected, got, err)
	}
	p, err := c.ReadConnected()
	if err != nil || string(p) != "hi" {
		t.Fatalf("packet %q %v", p, err)
	}
}

func TestUoTUnconnectedRoundTrip(t *testing.T) {
	var b bytes.Buffer
	c := NewUoTCodec(&b, &b)
	d := net.UDPDestination(net.ParseAddress("127.0.0.1"), 99)
	if e := c.WriteUnconnected(d, []byte("x")); e != nil {
		t.Fatal(e)
	}
	got, p, e := c.ReadUnconnected()
	if e != nil || got.Port != 99 || string(p) != "x" {
		t.Fatalf("%v %q %v", got, p, e)
	}
}
