package internet_test

import (
	"context"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/sys/unix"
)

func listenerSocketProtocol(t *testing.T, listener net.Listener) int {
	t.Helper()
	conn, ok := listener.(syscall.Conn)
	if !ok {
		t.Fatalf("listener %T has no syscall connection", listener)
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var protocol int
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		protocol, socketErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PROTOCOL)
	}); err != nil {
		t.Fatal(err)
	}
	if socketErr != nil {
		t.Fatal(socketErr)
	}
	return protocol
}

func TestDefaultListenerMPTCPPolicy(t *testing.T) {
	// Make an inherited MPTCP default observable, rather than relying on the
	// compiler's compatibility defaults or an already disabled kernel feature.
	t.Setenv("GODEBUG", os.Getenv("GODEBUG")+",multipathtcp=1")
	var controlConfig net.ListenConfig
	control, err := controlConfig.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	if protocol := listenerSocketProtocol(t, control); protocol != unix.IPPROTO_MPTCP {
		t.Skipf("positive control fell back to protocol %d; kernel MPTCP is unavailable", protocol)
	}

	for _, test := range []struct {
		name     string
		options  *internet.SocketConfig
		protocol int
	}{
		{name: "nil options", protocol: unix.IPPROTO_TCP},
		{name: "default options", options: &internet.SocketConfig{}, protocol: unix.IPPROTO_TCP},
		{name: "explicit disabled", options: &internet.SocketConfig{TcpMptcp: false}, protocol: unix.IPPROTO_TCP},
		{name: "explicit enabled", options: &internet.SocketConfig{TcpMptcp: true}, protocol: unix.IPPROTO_MPTCP},
	} {
		t.Run(test.name, func(t *testing.T) {
			var listener internet.DefaultListener
			conn, err := listener.Listen(context.Background(), &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, test.options)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if protocol := listenerSocketProtocol(t, conn); protocol != test.protocol {
				t.Fatalf("socket protocol = %d, want %d", protocol, test.protocol)
			}
		})
	}
}
