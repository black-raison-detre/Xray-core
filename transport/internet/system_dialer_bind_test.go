package internet

import (
	"bytes"
	"context"
	stderrors "errors"
	"fmt"
	stdnet "net"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"

	commonnet "github.com/xtls/xray-core/common/net"
)

func TestDefaultSystemDialerControllerErrorStopsTCPAndUDP(t *testing.T) {
	tcpListener, err := stdnet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()

	controllerErr := stderrors.New("controller failed")
	previousControllers := Controllers
	Controllers = []func(network, address string, c syscall.RawConn) error{
		func(string, string, syscall.RawConn) error { return controllerErr },
	}
	t.Cleanup(func() { Controllers = previousControllers })

	dialer := &DefaultSystemDialer{}
	tcpPort := commonnet.Port(tcpListener.Addr().(*stdnet.TCPAddr).Port)
	conn, err := dialer.Dial(context.Background(), nil, commonnet.TCPDestination(commonnet.ParseAddress("127.0.0.1"), tcpPort), nil)
	if conn != nil {
		_ = conn.Close()
	}
	if !stderrors.Is(err, controllerErr) {
		t.Fatalf("TCP dial error = %v, want controller error", err)
	}

	conn, err = dialer.Dial(context.Background(), nil, commonnet.UDPDestination(commonnet.ParseAddress("127.0.0.1"), 9), nil)
	if conn != nil {
		_ = conn.Close()
	}
	if !stderrors.Is(err, controllerErr) {
		t.Fatalf("UDP dial error = %v, want controller error", err)
	}
}

func TestDefaultSystemDialerKeepsOneDualStackPacketConnForMixedFamilies(t *testing.T) {
	server4, err := stdnet.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server4.Close()
	server6, err := stdnet.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback is unavailable: %v", err)
	}
	defer server6.Close()

	var requestedNetwork, requestedAddress, controlNetwork string
	stopPolicy, err := RegisterPacketConnPolicyFactory(func(requestedNetworkArg, requestedAddressArg string) *PacketConnPolicy {
		requestedNetwork, requestedAddress = requestedNetworkArg, requestedAddressArg
		return packetPolicyForFamilies(true, true, func(network, address string, _ syscall.RawConn) error {
			controlNetwork = network
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stopPolicy)

	destination4 := server4.LocalAddr().(*stdnet.UDPAddr)
	connection, err := (&DefaultSystemDialer{}).Dial(
		context.Background(), nil,
		commonnet.UDPDestination(commonnet.IPAddress(destination4.IP), commonnet.Port(destination4.Port)), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	wrapper, ok := connection.(*PacketConnWrapper)
	if !ok {
		t.Fatalf("system UDP connection type = %T; want *PacketConnWrapper", connection)
	}
	if requestedNetwork != "udp" || requestedAddress != "0.0.0.0:0" || controlNetwork != "udp6" {
		t.Fatalf("requested/control socket families = %q %q / %q; want the default IPv4 wildcard on a dual-stack udp6 socket", requestedNetwork, requestedAddress, controlNetwork)
	}

	payload4 := []byte("mixed-family-v4")
	payload6 := []byte("mixed-family-v6")
	if _, err := wrapper.Write(payload4); err != nil {
		t.Fatal(err)
	}
	if _, err := wrapper.WriteTo(payload6, server6.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	remote4 := readTestUDPPacket(t, server4, payload4)
	remote6 := readTestUDPPacket(t, server6, payload6)
	if _, err := server4.WriteTo([]byte("reply-v4"), remote4); err != nil {
		t.Fatal(err)
	}
	if _, err := server6.WriteTo([]byte("reply-v6"), remote6); err != nil {
		t.Fatal(err)
	}
	if got := readPacketConnReply(t, wrapper); !bytes.Equal(got, []byte("reply-v4")) && !bytes.Equal(got, []byte("reply-v6")) {
		t.Fatalf("unexpected dual-stack reply %q", got)
	} else if bytes.Equal(got, []byte("reply-v4")) {
		if other := readPacketConnReply(t, wrapper); !bytes.Equal(other, []byte("reply-v6")) {
			t.Fatalf("second dual-stack reply = %q; want reply-v6", other)
		}
	} else if other := readPacketConnReply(t, wrapper); !bytes.Equal(other, []byte("reply-v4")) {
		t.Fatalf("second dual-stack reply = %q; want reply-v4", other)
	}
}

func TestPacketConnFamilyGuardCapturesPlanAndWrapsUnderlyingPacketConn(t *testing.T) {
	server, err := stdnet.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	currentPolicy := packetPolicyForFamilies(true, false, nil)
	stopPolicy, err := RegisterPacketConnPolicyFactory(func(string, string) *PacketConnPolicy { return currentPolicy })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stopPolicy)

	localDestination := server.LocalAddr().(*stdnet.UDPAddr)
	destination := commonnet.UDPDestination(commonnet.IPAddress(localDestination.IP), commonnet.Port(localDestination.Port))
	connection, err := (&DefaultSystemDialer{}).Dial(context.Background(), nil, destination, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	wrapper, ok := connection.(*PacketConnWrapper)
	if !ok {
		t.Fatalf("system UDP connection type = %T; want *PacketConnWrapper", connection)
	}
	guard, ok := wrapper.PacketConn.(*packetConnFamilyGuard)
	if !ok {
		t.Fatalf("wrapped packet connection type = %T; want *packetConnFamilyGuard", wrapper.PacketConn)
	}
	remote6 := &commonnet.UDPAddr{IP: stdnet.ParseIP("2001:db8::1"), Port: 53}
	if _, err := wrapper.WriteTo([]byte("blocked"), remote6); err == nil {
		t.Fatal("PacketConnWrapper.WriteTo accepted an unselected IPv6 destination")
	}
	if _, err := wrapper.PacketConn.WriteTo([]byte("blocked"), remote6); err == nil {
		t.Fatal("unwrapped PacketConn.WriteTo bypassed the family guard")
	}

	currentPolicy = packetPolicyForFamilies(true, true, nil)
	if err := guard.policies[0].AllowDestination(remote6); err == nil {
		t.Fatal("existing socket adopted a later IPv6 selection")
	}
	if _, err := wrapper.WriteTo([]byte("still blocked"), remote6); err == nil {
		t.Fatal("existing socket guard changed after the packet-policy snapshot switched")
	}
	newConnection, err := (&DefaultSystemDialer{}).Dial(context.Background(), nil, destination, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer newConnection.Close()
	newWrapper := newConnection.(*PacketConnWrapper)
	newGuard := newWrapper.PacketConn.(*packetConnFamilyGuard)
	if err := newGuard.policies[0].AllowDestination(remote6); err != nil {
		t.Fatalf("new socket did not capture the refreshed IPv6 plan: %v", err)
	}

	payload := []byte("allowed-v4")
	if _, err := wrapper.Write(payload); err != nil {
		t.Fatal(err)
	}
	readTestUDPPacket(t, server, payload)
}

func TestPacketConnFamilyGuardProtectsWrapperAndExtractedPacketConnWrites(t *testing.T) {
	underlying := &writeCountingPacketConn{}
	policy := packetPolicyForFamilies(true, false, nil)
	guard := &packetConnFamilyGuard{PacketConn: underlying, policies: []*PacketConnPolicy{policy}}
	wrapper := &PacketConnWrapper{
		PacketConn: guard,
		Dest:       &commonnet.UDPAddr{IP: stdnet.ParseIP("192.0.2.10"), Port: 53},
	}
	remote6 := &commonnet.UDPAddr{IP: stdnet.ParseIP("2001:db8::1"), Port: 53}
	if _, err := wrapper.WriteTo([]byte("blocked"), remote6); err == nil {
		t.Fatal("PacketConnWrapper.WriteTo accepted an unselected family")
	}
	if _, err := wrapper.PacketConn.WriteTo([]byte("blocked"), remote6); err == nil {
		t.Fatal("extracted PacketConn.WriteTo bypassed the family guard")
	}
	if underlying.writes != 0 {
		t.Fatalf("family guard forwarded %d blocked packets", underlying.writes)
	}
	if _, err := wrapper.Write([]byte("allowed")); err != nil {
		t.Fatalf("PacketConnWrapper.Write rejected its selected family: %v", err)
	}
	if underlying.writes != 1 {
		t.Fatalf("selected-family packet count = %d; want 1", underlying.writes)
	}
}

type writeCountingPacketConn struct {
	stdnet.PacketConn
	writes int
}

func (conn *writeCountingPacketConn) WriteTo(payload []byte, _ stdnet.Addr) (int, error) {
	conn.writes++
	return len(payload), nil
}

func packetPolicyForFamilies(ipv4, ipv6 bool, control func(string, string, syscall.RawConn) error) *PacketConnPolicy {
	return &PacketConnPolicy{
		Control: control,
		AllowDestination: func(destination commonnet.Addr) error {
			udpAddress, ok := destination.(*commonnet.UDPAddr)
			if !ok || udpAddress.IP == nil {
				return fmt.Errorf("invalid UDP destination %v", destination)
			}
			if udpAddress.IP.IsLoopback() {
				return nil
			}
			if udpAddress.IP.To4() != nil && ipv4 || udpAddress.IP.To16() != nil && ipv6 {
				return nil
			}
			return fmt.Errorf("UDP destination family is unavailable: %s", udpAddress.IP)
		},
	}
}

func readTestUDPPacket(t *testing.T, connection stdnet.PacketConn, want []byte) stdnet.Addr {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len(want)+8)
	n, remote, err := connection.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buffer[:n], want) {
		t.Fatalf("received UDP payload %q; want %q", buffer[:n], want)
	}
	return remote
}

func readPacketConnReply(t *testing.T, connection stdnet.Conn) []byte {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	n, err := connection.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	return buffer[:n]
}

func TestApplyOutboundSocketOptionsClassifiesInterfaceBindingFailure(t *testing.T) {
	switch runtime.GOOS {
	case "darwin", "linux", "windows":
	default:
		t.Skip("interface binding is not implemented on this platform")
	}

	listener, err := stdnet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	interfaceName := ""
	for i := 0; interfaceName == ""; i++ {
		candidate := fmt.Sprintf("xraytest%d", os.Getpid()+i)
		if _, err := stdnet.InterfaceByName(candidate); err != nil {
			interfaceName = candidate
		}
	}

	rawConn, err := listener.(*stdnet.TCPListener).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var sockErr error
	if err := rawConn.Control(func(fd uintptr) {
		sockErr = applyOutboundSocketOptions("tcp4", listener.Addr().String(), fd, &SocketConfig{Interface: interfaceName})
	}); err != nil {
		t.Fatal(err)
	}
	var bindErr *BindError
	if !stderrors.As(sockErr, &bindErr) {
		t.Fatalf("socket option error = %v, want *BindError", sockErr)
	}

	dialer := &DefaultSystemDialer{}
	for _, dest := range []commonnet.Destination{
		commonnet.TCPDestination(commonnet.ParseAddress("127.0.0.1"), commonnet.Port(listener.Addr().(*stdnet.TCPAddr).Port)),
		commonnet.UDPDestination(commonnet.ParseAddress("127.0.0.1"), 9),
	} {
		conn, err := dialer.Dial(context.Background(), nil, dest, &SocketConfig{Interface: interfaceName})
		if conn != nil {
			_ = conn.Close()
		}
		if !stderrors.As(err, &bindErr) {
			t.Errorf("%s dial error = %v, want *BindError", dest.Network, err)
		}
	}
}
