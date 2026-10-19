//go:build routeros_gre

package gre

import (
	"encoding/binary"
	"errors"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// Fragment generation belongs to the simulated peer. Production GRE output is
// fragmented by the shared TUN stack before it reaches the raw device.
var nextFragmentID atomic.Uint32

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
