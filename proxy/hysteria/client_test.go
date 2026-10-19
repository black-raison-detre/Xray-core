package hysteria

import (
	"bytes"
	"testing"
)

func TestUDPReaderAcceptsLargeDatagram(t *testing.T) {
	data := bytes.Repeat([]byte("hysteria-udp-payload-"), 63)
	message := &UDPMessage{
		SessionID: 1,
		PacketID:  2,
		FragCount: 1,
		Addr:      "127.0.0.1:53",
		Data:      data,
	}
	wire := make([]byte, message.Size())
	n := message.Serialize(wire)
	if n <= 1200 || n > 1500 {
		t.Fatalf("test datagram is %d bytes; need to fit the 1500-byte receive buffer and exceed the old 1200-byte buffer", n)
	}

	reader := &UDPReader{
		reader: bytes.NewReader(wire[:n]),
		df:     &Defragger{},
	}
	got := make([]byte, len(data))
	read, addr, err := reader.ReadFrom(got)
	if err != nil {
		t.Fatal(err)
	}
	if read != len(data) || !bytes.Equal(got, data) {
		t.Fatalf("ReadFrom returned %d bytes, want %d matching payload", read, len(data))
	}
	if gotAddr := addr.String(); gotAddr != "udp:127.0.0.1:53" {
		t.Fatalf("ReadFrom returned address %q", gotAddr)
	}
}
