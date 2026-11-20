//go:build windows

package tun

import (
	"context"
	stdnet "net"
	"syscall"
	"testing"

	commonnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/egress"
	"github.com/xtls/xray-core/transport/internet"
)

type egressTestRawConn struct {
	controls int
}

func (c *egressTestRawConn) Control(fn func(uintptr)) error {
	c.controls++
	fn(123)
	return nil
}

func (*egressTestRawConn) Read(func(uintptr) (done bool)) error  { return nil }
func (*egressTestRawConn) Write(func(uintptr) (done bool)) error { return nil }

func TestConnectedUDP4AndUDP6DialerControllersBindSelectedFamily(t *testing.T) {
	ipv4 := &egress.Interface{Name: "fake-v4", Index: 4}
	ipv6 := &egress.Interface{Name: "fake-v6", IPv6Index: 6}
	selected := map[string]*egress.Interface{"udp4": ipv4, "udp6": ipv6}
	type binding struct {
		network string
		address string
		iface   *egress.Interface
	}
	var bindings []binding
	controller := makeEgressDialerController(
		func() bool { return false },
		func(network string) *egress.Interface { return selected[network] },
		func(network, address string, _ uintptr, iface *egress.Interface) error {
			bindings = append(bindings, binding{network: network, address: address, iface: iface})
			return nil
		},
	)

	// These are the normalized network names passed to net.Dialer.Control by
	// localdns and resolveOnOwn for connected resolver sockets. The fake RawConn
	// and binder exercise family selection without changing any host interface.
	for _, test := range []struct {
		network string
		address string
		iface   *egress.Interface
	}{
		{network: "udp4", address: "192.0.2.53:53", iface: ipv4},
		{network: "udp6", address: "2001:db8::53:53", iface: ipv6},
	} {
		raw := &egressTestRawConn{}
		if err := controller(test.network, test.address, raw); err != nil {
			t.Fatalf("controller(%s) error = %v", test.network, err)
		}
		if raw.controls != 1 {
			t.Errorf("controller(%s) called RawConn.Control %d times; want 1", test.network, raw.controls)
		}
	}
	if len(bindings) != 2 {
		t.Fatalf("connected UDP binding calls = %+v; want both address families", bindings)
	}
	if bindings[0].network != "udp4" || bindings[0].address != "192.0.2.53:53" || bindings[0].iface != ipv4 {
		t.Errorf("IPv4 binding = %+v", bindings[0])
	}
	if bindings[1].network != "udp6" || bindings[1].address != "2001:db8::53:53" || bindings[1].iface != ipv6 {
		t.Errorf("IPv6 binding = %+v", bindings[1])
	}
}

func TestDefaultSystemPacketConnUsesPolicyInsteadOfConnectedUDPBinding(t *testing.T) {
	var bindings, policyControls int
	controller := makeEgressDialerController(
		func() bool { return false },
		func(network string) *egress.Interface {
			return &egress.Interface{Name: "fake-" + network, Index: 4, IPv6Index: 6}
		},
		func(string, string, uintptr, *egress.Interface) error {
			bindings++
			return nil
		},
	)

	internet.ControllersLock.Lock()
	previousControllers := internet.Controllers
	internet.Controllers = []func(network, address string, connection syscall.RawConn) error{controller}
	internet.ControllersLock.Unlock()
	t.Cleanup(func() {
		internet.ControllersLock.Lock()
		internet.Controllers = previousControllers
		internet.ControllersLock.Unlock()
	})

	stopPolicy, err := internet.RegisterPacketConnPolicyFactory(func(string, string) *internet.PacketConnPolicy {
		return &internet.PacketConnPolicy{Control: func(network, _ string, connection syscall.RawConn) error {
			if internet.IsPacketConnControllerRawConn(connection) {
				t.Error("packet policy received the controller-only marker")
			}
			policyControls++
			return nil
		}}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stopPolicy)

	// ListenPacket creates only a local wildcard socket. No packet is sent and
	// the injected bind function never changes a host adapter.
	connection, err := (&internet.DefaultSystemDialer{}).Dial(
		context.Background(), nil,
		commonnet.UDPDestination(commonnet.ParseAddress("192.0.2.53"), 53), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if bindings != 0 {
		t.Fatalf("generic controller applied %d connected-UDP bindings to a packet-policy socket", bindings)
	}
	if policyControls != 1 {
		t.Fatalf("packet-policy controls = %d; want 1", policyControls)
	}
}

func TestNetDialerConnectedUDP4AndUDP6UseEgressController(t *testing.T) {
	if probe, err := stdnet.ListenPacket("udp6", "[::1]:0"); err != nil {
		t.Skipf("IPv6 loopback is unavailable: %v", err)
	} else {
		_ = probe.Close()
	}

	for _, test := range []struct {
		network string
		address string
	}{
		{network: "udp4", address: "192.0.2.53:53"},
		{network: "udp6", address: "[2001:db8::53]:53"},
	} {
		iface := &egress.Interface{Name: "fake-" + test.network, Index: 4, IPv6Index: 6}
		var bindings int
		controller := makeEgressDialerController(
			func() bool { return false },
			func(network string) *egress.Interface {
				if network != test.network {
					t.Fatalf("binding lookup network = %q; want %q", network, test.network)
				}
				return iface
			},
			func(network, address string, _ uintptr, selected *egress.Interface) error {
				if network != test.network || address != test.address || selected != iface {
					t.Errorf("connected UDP binding = %s %s %+v", network, address, selected)
				}
				bindings++
				return nil
			},
		)
		dialer := &stdnet.Dialer{Control: controller}
		conn, _ := dialer.DialContext(context.Background(), test.network, test.address)
		if conn != nil {
			_ = conn.Close()
		}
		if bindings != 1 {
			t.Errorf("net.Dialer connected %s calls to egress binder = %d; want 1", test.network, bindings)
		}
	}
}
