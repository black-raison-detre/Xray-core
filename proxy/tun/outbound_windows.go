//go:build windows

package tun

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"syscall"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/features/egress"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/sys/windows"
)

func configureOutboundInterface(handler *Handler, _ Tun, tunIndex int) error {
	interfaceName := handler.config.AutoOutboundsInterface
	if interfaceName == "auto" {
		interfaceName = ""
	}
	manager, err := egress.StartActive(egress.Options{
		InterfaceName: interfaceName,
		TunIndex:      uint32(tunIndex),
		TunName:       handler.config.Name,
	})
	if err != nil {
		return err
	}
	handler.egressManager = manager
	stopPacketPolicy, err := internet.RegisterPacketConnPolicyFactory(func(requestedNetwork, requestedAddress string) *internet.PacketConnPolicy {
		snapshot := manager.Snapshot()
		if snapshot.State == "inactive" {
			return nil
		}
		var ipv4, ipv6 *egress.Interface
		if snapshot.IPv4.State == "selected" {
			ipv4 = snapshot.IPv4.Interface
		}
		if snapshot.IPv6.State == "selected" {
			ipv6 = snapshot.IPv6.Interface
		}
		return &internet.PacketConnPolicy{
			Control: func(network, address string, connection syscall.RawConn) error {
				ipv4Socket, ipv6Socket, err := udpSocketFamilies(network, address, requestedNetwork, requestedAddress)
				if err != nil {
					return err
				}
				var controlErr, socketErr error
				controlErr = connection.Control(func(fd uintptr) {
					socketErr = setUDPFamilyInterfaces(network, address, fd, ipv4Socket, ipv6Socket, ipv4, ipv6)
				})
				if socketErr != nil {
					return socketErr
				}
				return controlErr
			},
			AllowDestination: func(destination net.Addr) error {
				udpAddress, ok := destination.(*net.UDPAddr)
				if !ok || udpAddress.IP == nil {
					return errors.New("UDP destination has no IP address")
				}
				if udpAddress.IP.IsLoopback() {
					return nil
				}
				if udpAddress.IP.To4() != nil {
					if ipv4 == nil {
						return errors.New("no selected IPv4 egress interface for UDP destination")
					}
					return nil
				}
				if udpAddress.IP.To16() != nil {
					if ipv6 == nil {
						return errors.New("no selected IPv6 egress interface for UDP destination")
					}
					return nil
				}
				return errors.New("UDP destination has an invalid IP address")
			},
		}
	})
	if err != nil {
		return err
	}
	handler.outboundClose = stopPacketPolicy

	internet.RegisterDialerController(func(network, address string, connection syscall.RawConn) error {
		if manager.Closed() {
			return nil
		}
		if strings.HasPrefix(strings.ToLower(network), "udp") {
			return nil
		}
		if !needsOutboundInterface(address) {
			return nil
		}
		iface := manager.BindingForNetwork(network)
		if iface == nil {
			errors.LogInfo(context.Background(), "[tun] no selected egress interface for ", network)
			return errors.New("egress interface not found for network ", network)
		}
		var controlErr, socketErr error
		controlErr = connection.Control(func(fd uintptr) {
			if err := setinterfaceFamily(network, address, fd, iface); err != nil {
				socketErr = errors.New("[tun] failed to set family egress interface").Base(err)
			}
		})
		if socketErr != nil {
			return socketErr
		}
		return controlErr
	})
	return nil
}

func udpSocketFamilies(network, address, requestedNetwork, requestedAddress string) (ipv4, ipv6 bool, err error) {
	switch network {
	case "udp4":
		return true, false, nil
	case "udp6":
		return true, true, nil
	case "udp":
		if strings.HasSuffix(requestedNetwork, "6") {
			return true, true, nil
		}
		if strings.HasSuffix(requestedNetwork, "4") {
			return true, false, nil
		}
		host, _, splitErr := net.SplitHostPort(requestedAddress)
		if splitErr != nil {
			return false, false, errors.New("unable to determine UDP socket family from ", address).Base(splitErr)
		}
		if strings.Contains(host, ":") {
			return true, true, nil
		}
		return true, false, nil
	default:
		return false, false, errors.New("unsupported UDP socket network ", network)
	}
}

func setUDPFamilyInterfaces(network, address string, fd uintptr, ipv4Socket, ipv6Socket bool, ipv4, ipv6 *egress.Interface) error {
	socket := windows.Handle(fd)
	var ipv4Err, ipv6Err error
	if ipv4Socket && ipv4 != nil {
		if ipv4.Index == 0 {
			ipv4Err = errors.New("IPv4 interface index is unavailable")
		} else {
			var index [4]byte
			binary.BigEndian.PutUint32(index[:], ipv4.Index)
			value := int(binary.NativeEndian.Uint32(index[:]))
			ipv4Err = windows.SetsockoptInt(socket, windows.IPPROTO_IP, IP_UNICAST_IF, value)
			if ipv4Err == nil {
				ipv4Err = windows.SetsockoptInt(socket, windows.IPPROTO_IP, windows.IP_MULTICAST_IF, value)
			}
		}
	}
	if ipv6Socket && ipv6 != nil {
		if ipv6.IPv6Index == 0 {
			ipv6Err = errors.New("IPv6 interface index is unavailable")
		} else {
			ipv6Err = windows.SetsockoptInt(socket, windows.IPPROTO_IPV6, IPV6_UNICAST_IF, int(ipv6.IPv6Index))
			if ipv6Err == nil {
				ipv6Err = windows.SetsockoptInt(socket, windows.IPPROTO_IPV6, windows.IPV6_MULTICAST_IF, int(ipv6.IPv6Index))
			}
		}
	}
	if ipv4Err != nil || ipv6Err != nil {
		return errors.New("failed to bind UDP ", network, " socket for ", address).Base(errors.Combine(ipv4Err, ipv6Err))
	}
	return nil
}

func setinterfaceFamily(network, address string, fd uintptr, iface *egress.Interface) error {
	socket := windows.Handle(fd)
	switch network {
	case "tcp6", "udp6", "ip6":
		if iface.IPv6Index == 0 {
			return errors.New("IPv6 interface index is unavailable")
		}
		first := windows.SetsockoptInt(socket, windows.IPPROTO_IPV6, IPV6_UNICAST_IF, int(iface.IPv6Index))
		var multicast error
		if network == "udp6" {
			multicast = windows.SetsockoptInt(socket, windows.IPPROTO_IPV6, windows.IPV6_MULTICAST_IF, int(iface.IPv6Index))
		}
		return errors.Combine(first, multicast)
	case "tcp4", "udp4", "ip4":
		if iface.Index == 0 {
			return errors.New("IPv4 interface index is unavailable")
		}
		var index [4]byte
		binary.BigEndian.PutUint32(index[:], iface.Index)
		value := int(binary.NativeEndian.Uint32(index[:]))
		first := windows.SetsockoptInt(socket, windows.IPPROTO_IP, IP_UNICAST_IF, value)
		var multicast error
		if network == "udp4" {
			multicast = windows.SetsockoptInt(socket, windows.IPPROTO_IP, windows.IP_MULTICAST_IF, value)
		}
		return errors.Combine(first, multicast)
	default:
		return errors.New("unsupported network ", network, " for ", address)
	}
}
