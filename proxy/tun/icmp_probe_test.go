package tun

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/observatory"
)

func TestStackICMPProbe(t *testing.T) {
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, mode := range []string{"fake", "probe", "unavailable", "closed"} {
			t.Run(family+"/"+mode, func(t *testing.T) {
				const delay = 20 * time.Millisecond
				l := newLink()
				replies := make(chan []byte, 1)
				l.out = func(b []byte) { replies <- b }
				h := &Handler{ctx: context.Background(), config: &Config{}}
				if mode != "fake" {
					h.config.IcmpMode = IcmpMode_PROBE
				}
				if mode == "probe" || mode == "closed" {
					h.observatory = &testObservatory{report: &observatory.ObservationResult{Status: []*observatory.OutboundStatus{{Alive: true, Delay: delay.Milliseconds()}}}}
				}
				s, err := NewStack(h.ctx, StackOptions{Tun: l, MTU: testMTU}, h)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				src, dst := netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("1.1.1.1")
				protocol, request, reply := byte(protoICMPv4), byte(8), byte(0)
				if family == "ipv6" {
					src, dst = netip.MustParseAddr("fd00::2"), netip.MustParseAddr("2606:4700:4700::1111")
					protocol, request, reply = protoICMPv6, 128, 129
				}
				var header [ipv6HeaderSize]byte
				n := putIPHeader(header[:], protocol, src, dst)
				message := []byte{request, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 0xaa, 0xbb}
				if protocol == protoICMPv4 {
					binary.BigEndian.PutUint16(message[2:], checksum(sum(message, 0)))
				} else {
					binary.BigEndian.PutUint16(message[2:], transportChecksum(header[:n], protocol, message, nil))
				}
				setIPLength(header[:n], n+len(message))
				packetBytes := append(append([]byte{}, header[:n]...), message...)
				started := time.Now()
				s.Input(packetBytes)
				// Reusing the input buffer must not corrupt a delayed response.
				clear(packetBytes)
				if mode == "closed" {
					if err := s.Close(); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "unavailable" || mode == "closed" {
					select {
					case <-replies:
						t.Fatal("echo reply was not suppressed")
					case <-time.After(2 * delay):
					}
					return
				}
				select {
				case data := <-replies:
					if mode == "probe" && time.Since(started) < delay {
						t.Fatal("echo reply arrived before cached delay")
					}
					p, ok := parsePacket(data, 0)
					if !ok || p.src != dst || p.dst != src || p.payload[0] != reply || !bytes.Equal(p.payload[4:], message[4:]) || !p.verified() {
						t.Fatalf("invalid echo response: %x", data)
					}
				case <-time.After(time.Second):
					t.Fatal("echo response did not arrive")
				}
			})
		}
	}
}

func TestICMPProbeSchedulerBoundsAndCloseDrains(t *testing.T) {
	s := &stack{}
	started, release := make(chan struct{}), make(chan struct{})
	if !s.scheduleICMPEchoReply(time.Millisecond, func() { close(started); <-release }) {
		t.Fatal("schedule failed")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("callback did not start")
	}
	for range maxPendingICMPEchoReply - 1 {
		if !s.scheduleICMPEchoReply(maxICMPProbeDelay, func() {}) {
			t.Fatal("pending limit too small")
		}
	}
	if s.scheduleICMPEchoReply(maxICMPProbeDelay, func() {}) {
		t.Fatal("pending limit was not enforced")
	}
	stopped := make(chan struct{})
	go func() { s.stopICMPEchoReplies(); close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("shutdown returned during callback")
	case <-time.After(10 * time.Millisecond):
	}
	close(release)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not drain")
	}
	if s.scheduleICMPEchoReply(time.Millisecond, func() {}) {
		t.Fatal("scheduler accepted work after close")
	}
}
