//go:build routeros_gre

package gre

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/features/extension"
	"github.com/xtls/xray-core/features/policy"
	"google.golang.org/protobuf/proto"
)

type testObservatory struct {
	report proto.Message
	err    error
}

func (*testObservatory) Type() interface{} { return extension.ObservatoryType() }
func (*testObservatory) Start() error      { return nil }
func (*testObservatory) Close() error      { return nil }
func (o *testObservatory) GetObservation(context.Context) (proto.Message, error) {
	return o.report, o.err
}

func TestHandlerICMPEchoDelay(t *testing.T) {
	handler := &Handler{ctx: context.Background(), config: &Config{IcmpMode: IcmpMode_PROBE}, observatory: &testObservatory{
		report: &observatory.ObservationResult{Status: []*observatory.OutboundStatus{
			{OutboundTag: "dead", Alive: false, Delay: 1},
			{OutboundTag: "slow", Alive: true, Delay: 80},
			{OutboundTag: "fast", Alive: true, Delay: 35},
		}},
	}}
	delay, ok := handler.icmpEchoDelay()
	if !ok || delay != 35*time.Millisecond {
		t.Fatalf("icmpEchoDelay() = (%s, %v)", delay, ok)
	}
	handler.observatory = &testObservatory{report: &observatory.ObservationResult{}}
	if _, ok := handler.icmpEchoDelay(); ok {
		t.Fatal("probe mode accepted an empty observation")
	}
	handler.config.IcmpMode = IcmpMode_FAKE
	if delay, ok := handler.icmpEchoDelay(); !ok || delay != 0 {
		t.Fatalf("fake icmpEchoDelay() = (%s, %v)", delay, ok)
	}
}

// Exercise Handler.Start as well as the cross-package callback: an unexported
// method assertion in package tun cannot discover gre.Handler.icmpEchoDelay.
func TestHandlerSharedStackICMP(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		for _, mode := range []string{"fake", "probe", "unavailable", "closed"} {
			t.Run(fmt.Sprintf("ipv6=%v/%s", ipv6, mode), func(t *testing.T) {
				device := newMemoryPacketDevice()
				originalFactory := createPacketDevice
				createPacketDevice = func(context.Context, runtimeConfig) (packetDevice, error) { return device, nil }
				t.Cleanup(func() { createPacketDevice = originalFactory })
				const delay = 20 * time.Millisecond
				h := &Handler{ctx: context.Background(), policyManager: testPolicyManager{}, config: &Config{
					LocalAddress: "172.31.255.2", RemoteAddress: "172.31.255.1",
					AllowedInnerSources: []string{"192.168.50.100/32", "2001:db8:50::/64"}, Mtu: 1400,
				}}
				if mode != "fake" {
					h.config.IcmpMode = IcmpMode_PROBE
				}
				if mode == "probe" || mode == "closed" {
					h.observatory = &testObservatory{report: &observatory.ObservationResult{Status: []*observatory.OutboundStatus{{Alive: true, Delay: delay.Milliseconds()}}}}
				}
				if err := h.Start(); err != nil {
					t.Fatal(err)
				}
				defer h.Close()
				request := testICMPEchoRequest(ipv6)
				decoded, err := decodeGREDatagram(testOuterGRE(testRuntimeConfig(t), request, false, 0), testRuntimeConfig(t))
				if err != nil {
					t.Fatal(err)
				}
				started := time.Now()
				// Direct input makes the close-before-delayed-reply case deterministic.
				h.stack.Input(decoded.innerPacket)
				if mode == "closed" {
					if err := h.Close(); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "unavailable" || mode == "closed" {
					select {
					case <-device.output:
						t.Fatal("unexpected ICMP reply")
					case <-time.After(2 * delay):
					}
					return
				}
				select {
				case reply := <-device.output:
					if mode == "probe" && time.Since(started) < delay {
						t.Fatal("reply arrived before cached delay")
					}
					offset, replyType := 20, byte(0)
					if ipv6 {
						offset, replyType = 40, 129
					}
					if len(reply) != len(request) || reply[offset] != replyType || !bytes.Equal(reply[offset+4:], request[offset+4:]) || testICMPChecksum(reply) != 0 {
						t.Fatalf("invalid echo response: %x", reply)
					}
				case <-time.After(time.Second):
					t.Fatal("ICMP response did not arrive")
				}
			})
		}
	}
}

type testPolicyManager struct{ policy.Manager }

func (testPolicyManager) ForLevel(uint32) policy.Session { return policy.SessionDefault() }

func testICMPEchoRequest(ipv6 bool) []byte {
	packet := testInnerIPv4(netip.MustParseAddr("192.168.50.100"), netip.MustParseAddr("198.51.100.10"), ipProtocolICMP, 11)
	offset, requestType := 20, byte(8)
	if ipv6 {
		packet = testInnerIPv6(netip.MustParseAddr("2001:db8:50::1"), netip.MustParseAddr("2001:db8:198:51::10"), ipProtocolICMPv6, 11)
		offset, requestType = 40, 128
	}
	copy(packet[offset:], []byte{requestType, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 0xaa, 0xbb, 0xcc})
	binary.BigEndian.PutUint16(packet[offset+2:], testICMPChecksum(packet))
	return packet
}

func testICMPChecksum(packet []byte) uint16 {
	if packet[0]>>4 == 4 {
		return checksum(packet[20:])
	}
	pseudo := make([]byte, 40, 40+len(packet)-40)
	copy(pseudo, packet[8:40])
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(packet)-40))
	pseudo[39] = ipProtocolICMPv6
	return checksum(append(pseudo, packet[40:]...))
}
