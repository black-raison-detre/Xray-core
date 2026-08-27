//go:build routeros_gre

package gre

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var nextFragmentID atomic.Uint32

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
	greRejectedFlags = 0x7c00
	greVersionMask   = 0x0007
)

type decodedGREDatagram struct {
	innerPacket     []byte
	networkProtocol tcpip.NetworkProtocolNumber
	keepaliveReply  []byte
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
		return decodedGREDatagram{}, errors.New("unsupported GRE routing, key, sequence, or recursion flags")
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
	return decodedGREDatagram{innerPacket: inner, networkProtocol: header.IPv4ProtocolNumber}, nil
}

func decodeInnerIPv6(inner []byte, config runtimeConfig) (decodedGREDatagram, error) {
	if len(inner) < header.IPv6MinimumSize || inner[0]>>4 != 6 {
		return decodedGREDatagram{}, errors.New("malformed inner IPv6 packet")
	}
	payloadLength := int(binary.BigEndian.Uint16(inner[4:6]))
	if payloadLength == 0 && len(inner) != header.IPv6MinimumSize {
		return decodedGREDatagram{}, errors.New("inner IPv6 jumbograms are unsupported")
	}
	if header.IPv6MinimumSize+payloadLength != len(inner) || len(inner) > int(config.mtu) {
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
	return decodedGREDatagram{innerPacket: inner, networkProtocol: header.IPv6ProtocolNumber}, nil
}

func validateIPv6Payload(inner []byte) error {
	payload := buffer.MakeWithData(inner[header.IPv6MinimumSize:])
	iterator := header.MakeIPv6PayloadIterator(header.IPv6ExtensionHeaderIdentifier(inner[6]), payload)
	defer iterator.Release()
	nonInitialFragment := false
	seenFragment := false
	for {
		payloadHeader, done, err := iterator.Next()
		if err != nil {
			return errors.New("malformed inner IPv6 extension header")
		}
		if done {
			return errors.New("unsupported inner IPv6 protocol")
		}
		switch payloadHeader := payloadHeader.(type) {
		case header.IPv6FragmentExtHdr:
			if seenFragment {
				return errors.New("multiple inner IPv6 fragment headers are unsupported")
			}
			seenFragment = true
			nonInitialFragment = payloadHeader.FragmentOffset() != 0
			payloadHeader.Release()
		case header.IPv6RawPayloadHeader:
			protocol := uint8(payloadHeader.Identifier)
			payloadHeader.Release()
			if nonInitialFragment {
				return nil
			}
			switch protocol {
			case ipProtocolTCP, ipProtocolUDP, ipProtocolICMPv6:
				return nil
			default:
				return errors.New("unsupported inner IPv6 protocol")
			}
		default:
			payloadHeader.Release()
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
	if len(inner) == 0 || len(inner) > int(mtu) {
		return 0, errors.New("invalid outbound inner IP packet")
	}
	switch inner[0] >> 4 {
	case 4:
		if len(inner) < header.IPv4MinimumSize || int(binary.BigEndian.Uint16(inner[2:4])) != len(inner) {
			return 0, errors.New("invalid outbound inner IPv4 packet")
		}
		return greProtocolIPv4, nil
	case 6:
		if len(inner) < header.IPv6MinimumSize || header.IPv6MinimumSize+int(binary.BigEndian.Uint16(inner[4:6])) != len(inner) {
			return 0, errors.New("invalid outbound inner IPv6 packet")
		}
		return greProtocolIPv6, nil
	default:
		return 0, errors.New("invalid outbound inner IP version")
	}
}

func fragmentIPPacket(inner []byte, mtu uint32) ([][]byte, error) {
	if len(inner) == 0 {
		return nil, errors.New("invalid outbound inner IP packet")
	}
	switch inner[0] >> 4 {
	case 4:
		return fragmentIPv4Packet(inner, mtu)
	case 6:
		return fragmentIPv6Packet(inner, mtu)
	default:
		return nil, errors.New("invalid outbound inner IP version")
	}
}

func fragmentIPv4Packet(inner []byte, mtu uint32) ([][]byte, error) {
	if len(inner) < 20 || inner[0]>>4 != 4 {
		return nil, errors.New("invalid outbound inner IPv4 packet")
	}
	headerLen := int(inner[0]&0x0f) * 4
	if headerLen < 20 || headerLen > len(inner) || int(binary.BigEndian.Uint16(inner[2:4])) != len(inner) {
		return nil, errors.New("invalid outbound inner IPv4 header")
	}
	if len(inner) <= int(mtu) {
		return [][]byte{append([]byte(nil), inner...)}, nil
	}
	fragmentField := binary.BigEndian.Uint16(inner[6:8])
	if fragmentField&0x4000 != 0 {
		return nil, errors.New("outbound inner IPv4 packet exceeds MTU with DF set")
	}
	if fragmentField&0x3fff != 0 {
		return nil, errors.New("outbound inner IPv4 fragment exceeds MTU")
	}
	maxPayload := (int(mtu) - headerLen) &^ 7
	if maxPayload < 8 {
		return nil, errors.New("MTU is too small for IPv4 fragmentation")
	}
	identification := binary.BigEndian.Uint16(inner[4:6])
	if identification == 0 {
		identification = uint16(nextFragmentID.Add(1))
		if identification == 0 {
			identification = uint16(nextFragmentID.Add(1))
		}
	}
	payload := inner[headerLen:]
	fragments := make([][]byte, 0, (len(payload)+maxPayload-1)/maxPayload)
	for offset := 0; offset < len(payload); offset += maxPayload {
		end := offset + maxPayload
		if end > len(payload) {
			end = len(payload)
		}
		fragment := make([]byte, headerLen+end-offset)
		copy(fragment[:headerLen], inner[:headerLen])
		copy(fragment[headerLen:], payload[offset:end])
		binary.BigEndian.PutUint16(fragment[2:4], uint16(len(fragment)))
		binary.BigEndian.PutUint16(fragment[4:6], identification)
		field := uint16(offset / 8)
		if end < len(payload) {
			field |= 0x2000
		}
		binary.BigEndian.PutUint16(fragment[6:8], field)
		fragment[10], fragment[11] = 0, 0
		binary.BigEndian.PutUint16(fragment[10:12], checksum(fragment[:headerLen]))
		fragments = append(fragments, fragment)
	}
	return fragments, nil
}

func fragmentIPv6Packet(inner []byte, mtu uint32) ([][]byte, error) {
	if len(inner) < header.IPv6MinimumSize || inner[0]>>4 != 6 || header.IPv6MinimumSize+int(binary.BigEndian.Uint16(inner[4:6])) != len(inner) {
		return nil, errors.New("invalid outbound inner IPv6 packet")
	}
	if mtu < 1280 {
		return nil, errors.New("MTU is too small for IPv6")
	}
	if len(inner) <= int(mtu) {
		return [][]byte{append([]byte(nil), inner...)}, nil
	}
	hasFragmentHeader, err := hasIPv6FragmentHeader(inner)
	if err != nil {
		return nil, err
	}
	if hasFragmentHeader {
		return nil, errors.New("outbound inner IPv6 fragment exceeds MTU")
	}
	insertOffset, previousNextHeaderOffset, fragmentNextHeader, err := ipv6FragmentInsertionPoint(inner)
	if err != nil {
		return nil, err
	}
	maxPayload := (int(mtu) - insertOffset - header.IPv6FragmentHeaderSize) &^ 7
	if maxPayload < header.IPv6FragmentExtHdrFragmentOffsetBytesPerUnit {
		return nil, errors.New("MTU is too small for IPv6 fragmentation")
	}
	fragmentable := inner[insertOffset:]
	identification := nextFragmentID.Add(1)
	if identification == 0 {
		identification = nextFragmentID.Add(1)
	}
	fragments := make([][]byte, 0, (len(fragmentable)+maxPayload-1)/maxPayload)
	for offset := 0; offset < len(fragmentable); offset += maxPayload {
		end := offset + maxPayload
		if end > len(fragmentable) {
			end = len(fragmentable)
		}
		fragment := make([]byte, insertOffset+header.IPv6FragmentHeaderSize+end-offset)
		copy(fragment[:insertOffset], inner[:insertOffset])
		fragment[previousNextHeaderOffset] = byte(header.IPv6FragmentExtHdrIdentifier)
		fragmentHeader := fragment[insertOffset : insertOffset+header.IPv6FragmentHeaderSize]
		fragmentHeader[0] = fragmentNextHeader
		fragmentField := uint16(offset/header.IPv6FragmentExtHdrFragmentOffsetBytesPerUnit) << 3
		if end < len(fragmentable) {
			fragmentField |= 1
		}
		binary.BigEndian.PutUint16(fragmentHeader[2:4], fragmentField)
		binary.BigEndian.PutUint32(fragmentHeader[4:8], identification)
		copy(fragment[insertOffset+header.IPv6FragmentHeaderSize:], fragmentable[offset:end])
		binary.BigEndian.PutUint16(fragment[4:6], uint16(len(fragment)-header.IPv6MinimumSize))
		fragments = append(fragments, fragment)
	}
	return fragments, nil
}

func hasIPv6FragmentHeader(inner []byte) (bool, error) {
	payload := buffer.MakeWithData(inner[header.IPv6MinimumSize:])
	iterator := header.MakeIPv6PayloadIterator(header.IPv6ExtensionHeaderIdentifier(inner[6]), payload)
	defer iterator.Release()
	for {
		payloadHeader, done, err := iterator.Next()
		if err != nil {
			return false, errors.New("malformed outbound inner IPv6 extension header")
		}
		if done {
			return false, nil
		}
		switch payloadHeader := payloadHeader.(type) {
		case header.IPv6FragmentExtHdr:
			payloadHeader.Release()
			return true, nil
		case header.IPv6RawPayloadHeader:
			payloadHeader.Release()
			return false, nil
		default:
			payloadHeader.Release()
		}
	}
}

func ipv6FragmentInsertionPoint(inner []byte) (int, int, byte, error) {
	offset := header.IPv6MinimumSize
	previousNextHeaderOffset := 6
	nextHeader := inner[previousNextHeaderOffset]
	consumeExtension := func() error {
		if offset+2 > len(inner) {
			return errors.New("malformed outbound inner IPv6 extension header")
		}
		headerLength := (int(inner[offset+1]) + 1) * 8
		if headerLength < 8 || offset+headerLength > len(inner) {
			return errors.New("malformed outbound inner IPv6 extension header")
		}
		previousNextHeaderOffset = offset
		nextHeader = inner[offset]
		offset += headerLength
		return nil
	}
	consumeExperimentExtension := func() error {
		if offset+header.IPv6ExperimentHdrLength > len(inner) {
			return errors.New("malformed outbound inner IPv6 experiment header")
		}
		previousNextHeaderOffset = offset
		nextHeader = inner[offset]
		offset += header.IPv6ExperimentHdrLength
		return nil
	}
	if nextHeader == byte(header.IPv6HopByHopOptionsExtHdrIdentifier) {
		if err := consumeExtension(); err != nil {
			return 0, 0, 0, err
		}
	}
	if nextHeader == byte(header.IPv6DestinationOptionsExtHdrIdentifier) {
		if offset+2 > len(inner) {
			return 0, 0, 0, errors.New("malformed outbound inner IPv6 destination options header")
		}
		candidateLength := (int(inner[offset+1]) + 1) * 8
		if candidateLength < 8 || offset+candidateLength > len(inner) {
			return 0, 0, 0, errors.New("malformed outbound inner IPv6 destination options header")
		}
		if inner[offset] == byte(header.IPv6RoutingExtHdrIdentifier) {
			if err := consumeExtension(); err != nil {
				return 0, 0, 0, err
			}
		}
	}
	for nextHeader == byte(header.IPv6RoutingExtHdrIdentifier) {
		if err := consumeExtension(); err != nil {
			return 0, 0, 0, err
		}
	}
	for nextHeader == byte(header.IPv6ExperimentExtHdrIdentifier) {
		if err := consumeExperimentExtension(); err != nil {
			return 0, 0, 0, err
		}
	}
	return offset, previousNextHeaderOffset, nextHeader, nil
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
