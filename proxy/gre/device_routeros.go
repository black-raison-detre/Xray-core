//go:build routeros_gre

package gre

import "github.com/xtls/xray-core/proxy/tun"

type packetDevice interface {
	tun.Tun
}

var createPacketDevice = newPacketDevice
