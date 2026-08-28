package packetstack

import (
	"encoding/binary"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestCalculateUDPChecksumEncodesZeroAsAllOnes(t *testing.T) {
	srcIP := tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	dstIP := tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	udpHeader := header.UDP(make([]byte, header.UDPMinimumSize))
	udpHeader.Encode(&header.UDPFields{SrcPort: 1234, DstPort: 5678, Length: header.UDPMinimumSize + 2})
	payload := make([]byte, 2)

	foundZero := false
	for value := range 1 << 16 {
		binary.BigEndian.PutUint16(payload, uint16(value))
		partial := header.PseudoHeaderChecksum(header.UDPProtocolNumber, srcIP, dstIP, udpHeader.Length())
		rawChecksum := ^udpHeader.CalculateChecksum(checksum.Checksum(payload, partial))
		if rawChecksum != 0 {
			continue
		}
		foundZero = true
		if got := calculateUDPChecksum(udpHeader, payload, srcIP, dstIP); got != 0xffff {
			t.Fatalf("checksum = %#04x, want 0xffff", got)
		}
		break
	}
	if !foundZero {
		t.Fatal("failed to construct a UDP datagram whose computed checksum is zero")
	}
}
