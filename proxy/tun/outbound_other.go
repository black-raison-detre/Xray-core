//go:build !windows

package tun

import (
	"context"
	"syscall"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
)

func configureOutboundInterface(handler *Handler, tunInterface Tun, tunIndex int) error {
	fixedName := handler.config.AutoOutboundsInterface
	if fixedName == "auto" {
		fixedName = ""
	}
	updater := &InterfaceUpdater{tunIndex: tunIndex, fixedName: fixedName}
	updater.Update()
	handler.outboundClose = updater.Close
	if setter, ok := tunInterface.(interface{ setOutboundUpdater(*InterfaceUpdater) }); ok {
		setter.setOutboundUpdater(updater)
	}

	internet.RegisterDialerController(func(network, address string, connection syscall.RawConn) error {
		if updater.Closed() {
			return nil
		}
		if !needsOutboundInterface(address) {
			return nil
		}
		iface := updater.Get()
		if iface == nil {
			errors.LogInfo(context.Background(), "[tun] failed to set interface: interface not found")
			return errors.New("interface not found")
		}
		var controlErr, socketErr error
		controlErr = connection.Control(func(fd uintptr) {
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
