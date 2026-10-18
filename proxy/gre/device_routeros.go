//go:build routeros_gre

package gre

import "gvisor.dev/gvisor/pkg/tcpip/stack"

type packetDevice interface {
	Start() error
	Close() error
	Endpoint() stack.LinkEndpoint
}

var createPacketDevice = newPacketDevice
