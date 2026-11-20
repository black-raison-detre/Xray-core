//go:build !windows

package tun

import (
	"context"
	"net/netip"
	"strings"
	"syscall"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
)

func configureOutboundInterface(handler *Handler, _ Tun, tunIndex int) error {
	if handler.config.GetAutoDns() {
		return errors.New("autoDNS is only supported on Windows")
	}
	fixedName := handler.config.AutoOutboundsInterface
	if fixedName == "" {
		return nil
	}
	if fixedName == "auto" {
		fixedName = ""
	}
	updater = &InterfaceUpdater{tunIndex: tunIndex, fixedName: fixedName}
	updater.Update()
	internet.RegisterDialerController(func(network, address string, c syscall.RawConn) error {
		iface := updater.Get()
		if iface == nil {
			errors.LogInfo(context.Background(), "[tun] failed to set interface: interface not found")
			return errors.New("interface not found")
		}
		var controlErr, socketErr error
		controlErr = c.Control(func(fd uintptr) {
			addrPort, err := netip.ParseAddrPort(address)
			if err == nil && addrPort.Addr().IsLoopback() || strings.HasPrefix(strings.ToLower(address), "localhost:") {
				return
			}
			if err := setinterface(network, address, fd, iface); err != nil {
				socketErr = errors.New("[tun] failed to set interface").Base(err)
			}
		})
		if socketErr != nil {
			return socketErr
		}
		return controlErr
	})
	return nil
}
