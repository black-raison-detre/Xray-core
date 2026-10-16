package internet

import (
	"context"
	stderrors "errors"
	"fmt"
	stdnet "net"
	"os"
	"runtime"
	"syscall"
	"testing"

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
