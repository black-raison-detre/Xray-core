//go:build routeros_gre

package gre

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestGREDatagramRoundTrip(t *testing.T) {
	config := testRuntimeConfig(t)
	inner := testInnerIPv4(config.allowed[0].Addr(), netip.MustParseAddr("198.51.100.10"), ipProtocolUDP, 32)
	for _, test := range []struct {
		name     string
		checksum bool
		reserved uint16
	}{
		{name: "base"},
		{name: "checksum", checksum: true},
		{name: "ignored reserved receive bits", reserved: 0x0100},
	} {
		t.Run(test.name, func(t *testing.T) {
			datagram := testOuterGRE(config, inner, test.checksum, test.reserved)
			decoded, err := decodeGREDatagram(datagram, config)
			if err != nil {
				t.Fatal(err)
			}
			got := decoded.innerPacket
			if decoded.keepaliveReply != nil {
				t.Fatal("ordinary packet was classified as a keepalive")
			}
			if decoded.networkProtocol != header.IPv4ProtocolNumber {
				t.Fatalf("network protocol = %d", decoded.networkProtocol)
			}
			if string(got) != string(inner) {
				t.Fatal("inner packet changed during decode")
			}
			encoded, err := encodeGREPacket(got, config.mtu)
			if err != nil {
				t.Fatal(err)
			}
			if binary.BigEndian.Uint16(encoded[:2]) != 0 || binary.BigEndian.Uint16(encoded[2:4]) != greProtocolIPv4 {
				t.Fatal("outbound GRE header is not the unchecksummed IPv4 base form")
			}
		})
	}
}

func TestGREDatagramAcceptsRouterOSKeepalive(t *testing.T) {
	config := testRuntimeConfig(t)
	inner := testInnerIPv4(config.local, config.remote, ipProtocolGRE, 4)
	packet := testOuterGRE(config, inner, false, 0)

	decoded, err := decodeGREDatagram(packet, config)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.innerPacket != nil {
		t.Fatal("RouterOS keepalive was passed to the ordinary IPv4 stack")
	}
	if len(decoded.keepaliveReply) != 4 || binary.BigEndian.Uint32(decoded.keepaliveReply) != 0 {
		t.Fatalf("keepalive reply = %x, want four-byte GRE protocol-type 0 header", decoded.keepaliveReply)
	}
}

func TestGREDatagramRejectsMalformedRouterOSKeepalives(t *testing.T) {
	config := testRuntimeConfig(t)
	tests := []struct {
		name          string
		outerChecksum bool
		extraPayload  bool
		mutate        func([]byte)
		want          string
	}{
		{name: "wrong inner source", mutate: func(p []byte) { copy(p[36:40], config.remote.AsSlice()); rewriteIPv4Checksum(p[24:]) }, want: "endpoints"},
		{name: "wrong inner destination", mutate: func(p []byte) { copy(p[40:44], config.local.AsSlice()); rewriteIPv4Checksum(p[24:]) }, want: "endpoints"},
		{name: "inner flags", mutate: func(p []byte) { binary.BigEndian.PutUint16(p[44:46], greChecksumFlag) }, want: "header"},
		{name: "inner protocol type", mutate: func(p []byte) { binary.BigEndian.PutUint16(p[46:48], greProtocolIPv4) }, want: "header"},
		{name: "outer reserved bits", mutate: func(p []byte) { binary.BigEndian.PutUint16(p[20:22], 0x0100) }, want: "optional headers"},
		{name: "outer checksum field", outerChecksum: true, want: "optional headers"},
		{name: "extra payload", extraPayload: true, want: "length"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inner := testInnerIPv4(config.local, config.remote, ipProtocolGRE, 4)
			packet := testOuterGRE(config, inner, test.outerChecksum, 0)
			if test.extraPayload {
				packet = append(packet, 0)
				binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
				innerOffset := len(packet) - len(inner) - 1
				binary.BigEndian.PutUint16(packet[innerOffset+2:innerOffset+4], uint16(len(inner)+1))
				rewriteIPv4Checksum(packet[innerOffset:])
				rewriteIPv4Checksum(packet)
			} else if test.mutate != nil {
				test.mutate(packet)
			}
			if _, err := decodeGREDatagram(packet, config); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("decode error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestGREDatagramRejectsMalformedAndSpoofedPackets(t *testing.T) {
	config := testRuntimeConfig(t)
	inner := testInnerIPv4(config.allowed[0].Addr(), netip.MustParseAddr("198.51.100.10"), ipProtocolTCP, 0)
	tests := []struct {
		name   string
		mutate func([]byte)
		want   string
	}{
		{name: "spoofed outer source", mutate: func(p []byte) { copy(p[12:16], netip.MustParseAddr("172.31.255.9").AsSlice()); rewriteIPv4Checksum(p) }, want: "endpoints"},
		{name: "key flag", mutate: func(p []byte) { binary.BigEndian.PutUint16(p[20:22], 0x2000) }, want: "flags"},
		{name: "non-ignorable reserved bit", mutate: func(p []byte) { binary.BigEndian.PutUint16(p[20:22], 0x0400) }, want: "flags"},
		{name: "version one", mutate: func(p []byte) { binary.BigEndian.PutUint16(p[20:22], 1) }, want: "version"},
		{name: "wrong protocol type", mutate: func(p []byte) { binary.BigEndian.PutUint16(p[22:24], greProtocolIPv6) }, want: "malformed inner IPv6"},
		{name: "bad inner source", mutate: func(p []byte) {
			copy(p[36:40], netip.MustParseAddr("192.168.50.99").AsSlice())
			rewriteIPv4Checksum(p[24:])
		}, want: "not allowed"},
		{name: "non-keepalive nested GRE", mutate: func(p []byte) { p[33] = ipProtocolGRE; rewriteIPv4Checksum(p[24:]) }, want: "keepalive"},
		{name: "recursive endpoint", mutate: func(p []byte) { copy(p[40:44], config.remote.AsSlice()); rewriteIPv4Checksum(p[24:]) }, want: "recurses"},
		{name: "bad total length", mutate: func(p []byte) { binary.BigEndian.PutUint16(p[2:4], uint16(len(p)-1)); rewriteIPv4Checksum(p) }, want: "total length"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			packet := testOuterGRE(config, inner, false, 0)
			test.mutate(packet)
			if _, err := decodeGREDatagram(packet, config); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("decode error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestGREDatagramRejectsBadChecksumOption(t *testing.T) {
	config := testRuntimeConfig(t)
	inner := testInnerIPv4(config.allowed[0].Addr(), netip.MustParseAddr("198.51.100.10"), ipProtocolICMP, 8)
	packet := testOuterGRE(config, inner, true, 0)
	packet[len(packet)-1] ^= 0xff
	if _, err := decodeGREDatagram(packet, config); err == nil || !strings.Contains(err.Error(), "GRE checksum") {
		t.Fatalf("decode error = %v, want GRE checksum rejection", err)
	}
}

func TestIPv6GREDatagramRoundTrip(t *testing.T) {
	config := testRuntimeConfig(t)
	for _, test := range []struct {
		name     string
		protocol byte
	}{{name: "tcp", protocol: ipProtocolTCP}, {name: "udp", protocol: ipProtocolUDP}, {name: "icmpv6", protocol: ipProtocolICMPv6}} {
		t.Run(test.name, func(t *testing.T) {
			inner := testInnerIPv6(config.allowed[1].Addr(), netip.MustParseAddr("2001:db8:198:51::10"), test.protocol, 32)
			inner = testIPv6ExtensionHeader(inner, byte(header.IPv6HopByHopOptionsExtHdrIdentifier))
			for _, withChecksum := range []bool{false, true} {
				datagram := testOuterGRE(config, inner, withChecksum, 0)
				decoded, err := decodeGREDatagram(datagram, config)
				if err != nil {
					t.Fatal(err)
				}
				if decoded.networkProtocol != header.IPv6ProtocolNumber || string(decoded.innerPacket) != string(inner) {
					t.Fatalf("decoded IPv6 packet changed: protocol=%d", decoded.networkProtocol)
				}
				encoded, err := encodeGREPacket(decoded.innerPacket, config.mtu)
				if err != nil {
					t.Fatal(err)
				}
				if got := binary.BigEndian.Uint16(encoded[2:4]); got != greProtocolIPv6 {
					t.Fatalf("GRE protocol type = %#x", got)
				}
			}
		})
	}
}

func TestIPv6GREDatagramAcceptsFragments(t *testing.T) {
	config := testRuntimeConfig(t)
	inner := testInnerIPv6(config.allowed[1].Addr(), netip.MustParseAddr("2001:db8:198:51::10"), ipProtocolUDP, 4096)
	fragments, err := fragmentIPv6Packet(inner, config.mtu)
	if err != nil {
		t.Fatal(err)
	}
	if len(fragments) < 2 {
		t.Fatalf("fragment count = %d", len(fragments))
	}
	for index, fragment := range fragments {
		decoded, err := decodeGREDatagram(testOuterGRE(config, fragment, false, 0), config)
		if err != nil {
			t.Fatalf("fragment %d: %v", index, err)
		}
		if decoded.networkProtocol != header.IPv6ProtocolNumber {
			t.Fatalf("fragment %d protocol = %d", index, decoded.networkProtocol)
		}
	}
}

func TestIPv6GREDatagramRejectsInvalidPackets(t *testing.T) {
	config := testRuntimeConfig(t)
	tests := []struct {
		name  string
		inner []byte
		want  string
	}{
		{name: "source", inner: testInnerIPv6(netip.MustParseAddr("2001:db8:51::1"), netip.MustParseAddr("2001:db8:198:51::10"), ipProtocolTCP, 8), want: "source"},
		{name: "protocol", inner: testInnerIPv6(config.allowed[1].Addr(), netip.MustParseAddr("2001:db8:198:51::10"), 132, 8), want: "protocol"},
		{name: "mapped source", inner: testInnerIPv6(netip.MustParseAddr("::ffff:192.0.2.1"), netip.MustParseAddr("2001:db8:198:51::10"), ipProtocolUDP, 8), want: "source"},
		{name: "mapped destination", inner: testInnerIPv6(config.allowed[1].Addr(), netip.MustParseAddr("::ffff:192.0.2.1"), ipProtocolUDP, 8), want: "destination"},
		{name: "over mtu", inner: testInnerIPv6(config.allowed[1].Addr(), netip.MustParseAddr("2001:db8:198:51::10"), ipProtocolUDP, 1400), want: "MTU"},
	}
	jumbo := testInnerIPv6(config.allowed[1].Addr(), netip.MustParseAddr("2001:db8:198:51::10"), ipProtocolUDP, 8)
	binary.BigEndian.PutUint16(jumbo[4:6], 0)
	tests = append(tests, struct {
		name  string
		inner []byte
		want  string
	}{name: "jumbogram", inner: jumbo, want: "jumbograms"})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodeGREDatagram(testOuterGRE(config, test.inner, false, 0), config); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("decode error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestFragmentIPv4Packet(t *testing.T) {
	source := netip.MustParseAddr("198.51.100.10")
	destination := netip.MustParseAddr("192.168.50.100")
	packet := testInnerIPv4(source, destination, ipProtocolUDP, 4096)
	fragments, err := fragmentIPv4Packet(packet, 1400)
	if err != nil {
		t.Fatal(err)
	}
	if len(fragments) < 2 {
		t.Fatalf("fragment count = %d", len(fragments))
	}
	identification := binary.BigEndian.Uint16(fragments[0][4:6])
	var payloadBytes int
	for index, fragment := range fragments {
		if len(fragment) > 1400 || checksum(fragment[:20]) != 0 {
			t.Fatalf("fragment %d is invalid: length=%d", index, len(fragment))
		}
		if binary.BigEndian.Uint16(fragment[4:6]) != identification {
			t.Fatalf("fragment %d identification differs", index)
		}
		field := binary.BigEndian.Uint16(fragment[6:8])
		if got := int(field&0x1fff) * 8; got != payloadBytes {
			t.Fatalf("fragment %d offset = %d, want %d", index, got, payloadBytes)
		}
		if index < len(fragments)-1 && field&0x2000 == 0 {
			t.Fatalf("fragment %d is missing MF", index)
		}
		if index == len(fragments)-1 && field&0x2000 != 0 {
			t.Fatal("last fragment has MF set")
		}
		payloadBytes += len(fragment) - 20
	}
	if payloadBytes != len(packet)-20 {
		t.Fatalf("fragment payload total = %d, want %d", payloadBytes, len(packet)-20)
	}
	packet[6] = 0x40
	rewriteIPv4Checksum(packet)
	if _, err := fragmentIPv4Packet(packet, 1400); err == nil || !strings.Contains(err.Error(), "DF") {
		t.Fatalf("DF fragmentation error = %v", err)
	}
}

func TestFragmentIPv6Packet(t *testing.T) {
	source := netip.MustParseAddr("2001:db8:198:51::10")
	destination := netip.MustParseAddr("2001:db8:50::100")
	packet := testInnerIPv6(source, destination, ipProtocolUDP, 4096)
	fragments, err := fragmentIPv6Packet(packet, 1400)
	if err != nil {
		t.Fatal(err)
	}
	if len(fragments) < 2 {
		t.Fatalf("fragment count = %d", len(fragments))
	}
	identification := binary.BigEndian.Uint32(fragments[0][44:48])
	var fragmentable []byte
	for index, fragment := range fragments {
		if len(fragment) > 1400 || fragment[6] != byte(header.IPv6FragmentExtHdrIdentifier) {
			t.Fatalf("fragment %d is invalid: length=%d next=%d", index, len(fragment), fragment[6])
		}
		if got := int(binary.BigEndian.Uint16(fragment[4:6])) + header.IPv6MinimumSize; got != len(fragment) {
			t.Fatalf("fragment %d length field = %d, want %d", index, got, len(fragment))
		}
		if got := binary.BigEndian.Uint32(fragment[44:48]); got != identification || got == 0 {
			t.Fatalf("fragment %d identification = %d", index, got)
		}
		field := binary.BigEndian.Uint16(fragment[42:44])
		if got := int(field>>3) * 8; got != len(fragmentable) {
			t.Fatalf("fragment %d offset = %d, want %d", index, got, len(fragmentable))
		}
		if index < len(fragments)-1 && field&1 == 0 {
			t.Fatalf("fragment %d is missing M flag", index)
		}
		if index == len(fragments)-1 && field&1 != 0 {
			t.Fatal("last fragment has M flag")
		}
		fragmentable = append(fragmentable, fragment[48:]...)
	}
	if string(fragmentable) != string(packet[header.IPv6MinimumSize:]) {
		t.Fatal("fragmentable payload did not reassemble")
	}
}

func TestFragmentIPv6PacketPreservesUnfragmentableHeaders(t *testing.T) {
	packet := testInnerIPv6(netip.MustParseAddr("2001:db8:1::1"), netip.MustParseAddr("2001:db8:2::1"), ipProtocolUDP, 4096)
	packet = testIPv6ExtensionHeader(packet, byte(header.IPv6DestinationOptionsExtHdrIdentifier))
	packet = testIPv6ExtensionHeader(packet, byte(header.IPv6RoutingExtHdrIdentifier))
	packet = testIPv6ExtensionHeader(packet, byte(header.IPv6DestinationOptionsExtHdrIdentifier))
	packet = testIPv6ExtensionHeader(packet, byte(header.IPv6HopByHopOptionsExtHdrIdentifier))
	fragments, err := fragmentIPv6Packet(packet, 1400)
	if err != nil {
		t.Fatal(err)
	}
	const insertionOffset = header.IPv6MinimumSize + 3*8
	for index, fragment := range fragments {
		if fragment[insertionOffset] != byte(header.IPv6DestinationOptionsExtHdrIdentifier) {
			t.Fatalf("fragment %d fragment next header = %d", index, fragment[insertionOffset])
		}
		if fragment[insertionOffset-8] != byte(header.IPv6FragmentExtHdrIdentifier) {
			t.Fatalf("fragment %d routing next header = %d", index, fragment[insertionOffset-8])
		}
	}
}

func TestFragmentIPv6PacketPreservesExperimentHeader(t *testing.T) {
	config := testRuntimeConfig(t)
	packet := testInnerIPv6(config.allowed[1].Addr(), netip.MustParseAddr("2001:db8:2::1"), ipProtocolUDP, 4096)
	packet = testIPv6ExtensionHeader(packet, byte(header.IPv6ExperimentExtHdrIdentifier))
	fragments, err := fragmentIPv6Packet(packet, 1400)
	if err != nil {
		t.Fatal(err)
	}
	for index, fragment := range fragments {
		if fragment[6] != byte(header.IPv6ExperimentExtHdrIdentifier) || fragment[header.IPv6MinimumSize] != byte(header.IPv6FragmentExtHdrIdentifier) {
			t.Fatalf("fragment %d extension chain = %d -> %d", index, fragment[6], fragment[header.IPv6MinimumSize])
		}
		if _, err := decodeGREDatagram(testOuterGRE(config, fragment, false, 0), config); err != nil {
			t.Fatalf("fragment %d rejected: %v", index, err)
		}
	}
}

func TestFragmentIPv6PacketRejectsOversizedFragment(t *testing.T) {
	packet := testInnerIPv6(netip.MustParseAddr("2001:db8:1::1"), netip.MustParseAddr("2001:db8:2::1"), ipProtocolUDP, 4096)
	fragments, err := fragmentIPv6Packet(packet, 1400)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fragmentIPv6Packet(fragments[0], 1280); err == nil || !strings.Contains(err.Error(), "fragment exceeds MTU") {
		t.Fatalf("fragmentation error = %v", err)
	}
}

func testRuntimeConfig(t *testing.T) runtimeConfig {
	t.Helper()
	config, err := makeRuntimeConfig(&Config{
		LocalAddress: "172.31.255.2", RemoteAddress: "172.31.255.1",
		AllowedInnerSources: []string{"192.168.50.100/32", "2001:db8:50::/64"}, Mtu: 1400,
	})
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func testInnerIPv6(source, destination netip.Addr, protocol byte, payloadSize int) []byte {
	packet := make([]byte, header.IPv6MinimumSize+payloadSize)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(payloadSize))
	packet[6] = protocol
	packet[7] = 64
	copy(packet[8:24], source.AsSlice())
	copy(packet[24:40], destination.AsSlice())
	return packet
}

func testIPv6ExtensionHeader(packet []byte, extensionType byte) []byte {
	extended := make([]byte, len(packet)+8)
	copy(extended[:header.IPv6MinimumSize], packet[:header.IPv6MinimumSize])
	extended[6] = extensionType
	extended[header.IPv6MinimumSize] = packet[6]
	copy(extended[header.IPv6MinimumSize+8:], packet[header.IPv6MinimumSize:])
	binary.BigEndian.PutUint16(extended[4:6], uint16(len(extended)-header.IPv6MinimumSize))
	return extended
}

func testInnerIPv4(source, destination netip.Addr, protocol byte, payloadSize int) []byte {
	packet := make([]byte, 20+payloadSize)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = protocol
	copy(packet[12:16], source.AsSlice())
	copy(packet[16:20], destination.AsSlice())
	rewriteIPv4Checksum(packet)
	return packet
}

func testOuterGRE(config runtimeConfig, inner []byte, withChecksum bool, reserved uint16) []byte {
	greHeaderLen := 4
	flags := reserved
	if withChecksum {
		greHeaderLen = 8
		flags |= greChecksumFlag
	}
	packet := make([]byte, 20+greHeaderLen+len(inner))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = ipProtocolGRE
	copy(packet[12:16], config.remote.AsSlice())
	copy(packet[16:20], config.local.AsSlice())
	rewriteIPv4Checksum(packet)
	grePacket := packet[20:]
	binary.BigEndian.PutUint16(grePacket[:2], flags)
	protocolType := uint16(greProtocolIPv4)
	if len(inner) > 0 && inner[0]>>4 == 6 {
		protocolType = greProtocolIPv6
	}
	binary.BigEndian.PutUint16(grePacket[2:4], protocolType)
	copy(grePacket[greHeaderLen:], inner)
	if withChecksum {
		binary.BigEndian.PutUint16(grePacket[4:6], checksum(grePacket))
	}
	return packet
}

func rewriteIPv4Checksum(packet []byte) {
	headerLen := int(packet[0]&0x0f) * 4
	packet[10], packet[11] = 0, 0
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:headerLen]))
}
