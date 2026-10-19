//go:build routeros_gre

package gre

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const (
	greProtocolIPv4  = 0x0800
	greProtocolIPv6  = 0x86dd
	greProtocolNone  = 0
	ipProtocolICMP   = 1
	ipProtocolTCP    = 6
	ipProtocolUDP    = 17
	ipProtocolGRE    = 47
	ipProtocolICMPv6 = 58
	greChecksumFlag  = 0x8000
	// RFC 2784 requires receivers to reject bits 1-5 and ignore bits 6-12.
	greRejectedFlags = 0x7c00
	greVersionMask   = 0x0007
)

type decodedGREDatagram struct {
	innerPacket    []byte
	keepaliveReply []byte
}

type runtimeConfig struct {
	local   netip.Addr
	remote  netip.Addr
	allowed []netip.Prefix
	mtu     uint32
}

func makeRuntimeConfig(config *Config) (runtimeConfig, error) {
	local, err := netip.ParseAddr(config.GetLocalAddress())
	if err != nil || !local.Is4() || !local.IsGlobalUnicast() {
		return runtimeConfig{}, errors.New("localAddress must be a unicast IPv4 address")
	}
	remote, err := netip.ParseAddr(config.GetRemoteAddress())
	if err != nil || !remote.Is4() || !remote.IsGlobalUnicast() {
		return runtimeConfig{}, errors.New("remoteAddress must be a unicast IPv4 address")
	}
	if local == remote {
		return runtimeConfig{}, errors.New("localAddress and remoteAddress must differ")
	}
	if len(config.GetAllowedInnerSources()) == 0 {
		return runtimeConfig{}, errors.New("allowedInnerSources must not be empty")
	}
	allowed := make([]netip.Prefix, 0, len(config.GetAllowedInnerSources()))
	hasIPv6 := false
	for _, value := range config.GetAllowedInnerSources() {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Is4In6() {
			return runtimeConfig{}, fmt.Errorf("invalid allowedInnerSources entry %q", value)
		}
		hasIPv6 = hasIPv6 || prefix.Addr().Is6()
		allowed = append(allowed, prefix.Masked())
	}
	mtu := config.GetMtu()
	if mtu == 0 {
		mtu = 1400
	}
	if mtu < 576 || mtu > 1472 {
		return runtimeConfig{}, errors.New("mtu must be 576..1472")
	}
	if hasIPv6 && mtu < 1280 {
		return runtimeConfig{}, errors.New("mtu must be 1280..1472 when IPv6 inner sources are configured")
	}
	return runtimeConfig{local: local, remote: remote, allowed: allowed, mtu: mtu}, nil
}

func decodeGREDatagram(datagram []byte, config runtimeConfig) (decodedGREDatagram, error) {
	if len(datagram) < 20 || datagram[0]>>4 != 4 {
		return decodedGREDatagram{}, errors.New("malformed outer IPv4 packet")
	}
	outerHeaderLen := int(datagram[0]&0x0f) * 4
	if outerHeaderLen < 20 || outerHeaderLen > len(datagram) {
		return decodedGREDatagram{}, errors.New("invalid outer IPv4 header length")
	}
	outerLen := int(binary.BigEndian.Uint16(datagram[2:4]))
	if outerLen != len(datagram) || outerLen < outerHeaderLen+4 {
		return decodedGREDatagram{}, errors.New("invalid outer IPv4 total length")
	}
	if checksum(datagram[:outerHeaderLen]) != 0 {
		return decodedGREDatagram{}, errors.New("invalid outer IPv4 checksum")
	}
	if datagram[9] != ipProtocolGRE {
		return decodedGREDatagram{}, errors.New("outer packet is not GRE")
	}
	if binary.BigEndian.Uint16(datagram[6:8])&0x3fff != 0 {
		return decodedGREDatagram{}, errors.New("fragmented outer IPv4 packet is unsupported")
	}
	if netip.AddrFrom4([4]byte(datagram[12:16])) != config.remote || netip.AddrFrom4([4]byte(datagram[16:20])) != config.local {
		return decodedGREDatagram{}, errors.New("unexpected outer IPv4 endpoints")
	}

	grePacket := datagram[outerHeaderLen:outerLen]
	flags := binary.BigEndian.Uint16(grePacket[:2])
	if flags&greVersionMask != 0 {
		return decodedGREDatagram{}, errors.New("unsupported GRE version")
	}
	if flags&greRejectedFlags != 0 {
		return decodedGREDatagram{}, errors.New("unsupported GRE optional-header or non-ignorable flags")
	}
	protocolType := binary.BigEndian.Uint16(grePacket[2:4])
	greHeaderLen := 4
	if flags&greChecksumFlag != 0 {
		greHeaderLen = 8
		if len(grePacket) < greHeaderLen {
			return decodedGREDatagram{}, errors.New("truncated GRE checksum header")
		}
		if binary.BigEndian.Uint16(grePacket[6:8]) != 0 {
			return decodedGREDatagram{}, errors.New("GRE Reserved1 must be zero")
		}
		if checksum(grePacket) != 0 {
			return decodedGREDatagram{}, errors.New("invalid GRE checksum")
		}
	}
	inner := grePacket[greHeaderLen:]
	switch protocolType {
	case greProtocolIPv4:
		return decodeInnerIPv4(inner, flags, outerHeaderLen, greHeaderLen, config)
	case greProtocolIPv6:
		return decodeInnerIPv6(inner, config)
	default:
		return decodedGREDatagram{}, errors.New("unsupported GRE payload protocol type")
	}
}

func decodeInnerIPv4(inner []byte, outerGREFlags uint16, outerHeaderLen, outerGREHeaderLen int, config runtimeConfig) (decodedGREDatagram, error) {
	if len(inner) < 20 || inner[0]>>4 != 4 {
		return decodedGREDatagram{}, errors.New("malformed inner IPv4 packet")
	}
	innerHeaderLen := int(inner[0]&0x0f) * 4
	if innerHeaderLen < 20 || innerHeaderLen > len(inner) {
		return decodedGREDatagram{}, errors.New("invalid inner IPv4 header length")
	}
	innerLen := int(binary.BigEndian.Uint16(inner[2:4]))
	if innerLen != len(inner) || innerLen > int(config.mtu) {
		return decodedGREDatagram{}, errors.New("invalid inner IPv4 total length or MTU")
	}
	if checksum(inner[:innerHeaderLen]) != 0 {
		return decodedGREDatagram{}, errors.New("invalid inner IPv4 checksum")
	}
	if inner[9] == ipProtocolGRE {
		keepaliveReply, err := decodeRouterOSKeepalive(inner, outerGREFlags, outerHeaderLen, outerGREHeaderLen, innerHeaderLen, config)
		if err != nil {
			return decodedGREDatagram{}, err
		}
		return decodedGREDatagram{keepaliveReply: keepaliveReply}, nil
	}
	source := netip.AddrFrom4([4]byte(inner[12:16]))
	if !source.IsGlobalUnicast() || !containsSource(config.allowed, source) {
		return decodedGREDatagram{}, errors.New("inner IPv4 source is not allowed")
	}
	destination := netip.AddrFrom4([4]byte(inner[16:20]))
	if destination == config.local || destination == config.remote {
		return decodedGREDatagram{}, errors.New("inner IPv4 destination recurses to a GRE endpoint")
	}
	switch inner[9] {
	case ipProtocolTCP, ipProtocolUDP, ipProtocolICMP:
	default:
		return decodedGREDatagram{}, errors.New("unsupported inner IPv4 protocol")
	}
	return decodedGREDatagram{innerPacket: inner}, nil
}

func decodeInnerIPv6(inner []byte, config runtimeConfig) (decodedGREDatagram, error) {
	if len(inner) < 40 || inner[0]>>4 != 6 {
		return decodedGREDatagram{}, errors.New("malformed inner IPv6 packet")
	}
	payloadLength := int(binary.BigEndian.Uint16(inner[4:6]))
	if payloadLength == 0 && len(inner) != 40 {
		return decodedGREDatagram{}, errors.New("inner IPv6 jumbograms are unsupported")
	}
	if 40+payloadLength != len(inner) || len(inner) > int(config.mtu) {
		return decodedGREDatagram{}, errors.New("invalid inner IPv6 payload length or MTU")
	}
	source := netip.AddrFrom16([16]byte(inner[8:24]))
	if source.Is4In6() || !source.IsGlobalUnicast() || !containsSource(config.allowed, source) {
		return decodedGREDatagram{}, errors.New("inner IPv6 source is not allowed")
	}
	destination := netip.AddrFrom16([16]byte(inner[24:40]))
	if destination.Is4In6() {
		return decodedGREDatagram{}, errors.New("inner IPv6 destination is IPv4-mapped")
	}
	if err := validateIPv6Payload(inner); err != nil {
		return decodedGREDatagram{}, err
	}
	return decodedGREDatagram{innerPacket: inner}, nil
}

// validateIPv6Payload checks extension lengths and the allowed transport without
// allocating gVisor packet buffers. Reassembly and transport checksums belong to
// the shared stack; non-initial fragments do not contain transport headers.
func validateIPv6Payload(inner []byte) error {
	next, offset := inner[6], 40
	seenFragment := false
	for {
		switch next {
		case ipProtocolTCP, ipProtocolUDP, ipProtocolICMPv6:
			return nil
		case 0, 43, 60, 253: // hop-by-hop, routing, destination options, experiment
			if offset+8 > len(inner) {
				return errors.New("malformed inner IPv6 extension header")
			}
			size := (int(inner[offset+1]) + 1) * 8
			if next == 253 {
				size = 8
			}
			if offset+size > len(inner) {
				return errors.New("malformed inner IPv6 extension header")
			}
			next, offset = inner[offset], offset+size
		case 44: // fragment
			if seenFragment {
				return errors.New("multiple inner IPv6 fragment headers are unsupported")
			}
			if offset+8 > len(inner) {
				return errors.New("malformed inner IPv6 fragment header")
			}
			seenFragment = true
			if binary.BigEndian.Uint16(inner[offset+2:offset+4])&0xfff8 != 0 {
				return nil
			}
			next, offset = inner[offset], offset+8
		default:
			return errors.New("unsupported inner IPv6 protocol")
		}
	}
}

func decodeRouterOSKeepalive(inner []byte, outerGREFlags uint16, outerHeaderLen, outerGREHeaderLen, innerHeaderLen int, config runtimeConfig) ([]byte, error) {
	if outerGREFlags != 0 || outerHeaderLen != 20 || outerGREHeaderLen != 4 || innerHeaderLen != 20 || len(inner) != 24 {
		return nil, errors.New("invalid RouterOS GRE keepalive length or optional headers")
	}
	if binary.BigEndian.Uint16(inner[6:8])&0x3fff != 0 {
		return nil, errors.New("fragmented RouterOS GRE keepalive is unsupported")
	}
	if netip.AddrFrom4([4]byte(inner[12:16])) != config.local || netip.AddrFrom4([4]byte(inner[16:20])) != config.remote {
		return nil, errors.New("invalid RouterOS GRE keepalive endpoints")
	}
	innerGRE := inner[innerHeaderLen:]
	if binary.BigEndian.Uint16(innerGRE[:2]) != 0 || binary.BigEndian.Uint16(innerGRE[2:4]) != greProtocolNone {
		return nil, errors.New("invalid RouterOS GRE keepalive header")
	}
	return innerGRE, nil
}

func encodeGREPacket(inner []byte, mtu uint32) ([]byte, error) {
	protocolType, err := outboundGREProtocol(inner, mtu)
	if err != nil {
		return nil, err
	}
	packet := make([]byte, 4+len(inner))
	binary.BigEndian.PutUint16(packet[2:4], protocolType)
	copy(packet[4:], inner)
	return packet, nil
}

func outboundGREProtocol(inner []byte, mtu uint32) (uint16, error) {
	return outboundGREProtocolParts(inner, 0, mtu)
}

func outboundGREProtocolParts(header []byte, payloadSize int, mtu uint32) (uint16, error) {
	size := len(header) + payloadSize
	if len(header) == 0 || size > int(mtu) {
		return 0, errors.New("invalid outbound inner IP packet")
	}
	switch header[0] >> 4 {
	case 4:
		if len(header) < 20 || int(binary.BigEndian.Uint16(header[2:4])) != size {
			return 0, errors.New("invalid outbound inner IPv4 packet")
		}
		return greProtocolIPv4, nil
	case 6:
		if len(header) < 40 || 40+int(binary.BigEndian.Uint16(header[4:6])) != size {
			return 0, errors.New("invalid outbound inner IPv6 packet")
		}
		return greProtocolIPv6, nil
	default:
		return 0, errors.New("invalid outbound inner IP version")
	}
}

func containsSource(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func checksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
