package tun

import (
	"fmt"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSetInterfaceSocketFamily(t *testing.T) {
	iface, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	for _, network := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
		for _, v6only := range []int{0, 1} {
			if network[3] == '4' && v6only != 0 {
				continue
			}
			t.Run(fmt.Sprintf("%s/v6only=%d", network, v6only), func(t *testing.T) {
				family, level, option := unix.AF_INET, unix.IPPROTO_IP, unix.IP_BOUND_IF
				if network[3] == '6' {
					family, level, option = unix.AF_INET6, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
				}
				socketType := unix.SOCK_STREAM
				if network[:3] == "udp" {
					socketType = unix.SOCK_DGRAM
				}
				fd, err := unix.Socket(family, socketType, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer unix.Close(fd)
				if family == unix.AF_INET6 {
					if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, v6only); err != nil {
						t.Fatal(err)
					}
				}
				if err := setinterface(network, "", uintptr(fd), iface); err != nil {
					t.Fatal(err)
				}
				index, err := unix.GetsockoptInt(fd, level, option)
				if err != nil {
					t.Fatal(err)
				}
				if index != iface.Index {
					t.Fatalf("bound interface index = %d, want %d", index, iface.Index)
				}
			})
		}
	}
}
