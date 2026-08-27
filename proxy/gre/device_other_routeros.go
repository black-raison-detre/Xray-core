//go:build routeros_gre && !linux

package gre

import (
	"context"
	"errors"
)

func newPacketDevice(context.Context, runtimeConfig) (packetDevice, error) {
	return nil, errors.New("GRE inbound requires Linux")
}
