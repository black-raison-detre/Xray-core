package tun

import (
	"context"

	"github.com/xtls/xray-core/proxy/internal/packetstack"
)

func NewStack(ctx context.Context, options StackOptions, handler *Handler) (Stack, error) {
	endpoint, err := options.Tun.newEndpoint()
	if err != nil {
		return nil, err
	}
	return packetstack.New(ctx, packetstack.Options{
		Endpoint:         endpoint,
		IdleTimeout:      options.IdleTimeout,
		HandleConnection: handler.HandleConnection,
		ICMPEchoDelay:    handler.icmpEchoDelay,
		LogPrefix:        "tun",
	})
}
