//go:build !routeros_gre

package conf

import (
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/tun"
	"google.golang.org/protobuf/proto"
)

type TunConfig struct {
	Name                   string   `json:"name"`
	MTU                    uint32   `json:"mtu"`
	Gateway                []string `json:"gateway"`
	DNS                    []string `json:"dns"`
	UserLevel              uint32   `json:"userLevel"`
	AutoSystemRoutingTable []string `json:"autoSystemRoutingTable"`
	AutoOutboundsInterface *string  `json:"autoOutboundsInterface"`
	ICMPMode               string   `json:"icmpMode"`
}

func (v *TunConfig) Build() (proto.Message, error) {
	config := &tun.Config{
		Name:                   v.Name,
		MTU:                    v.MTU,
		Gateway:                v.Gateway,
		DNS:                    v.DNS,
		UserLevel:              v.UserLevel,
		AutoSystemRoutingTable: v.AutoSystemRoutingTable,
	}
	if v.AutoOutboundsInterface != nil {
		config.AutoOutboundsInterface = *v.AutoOutboundsInterface
	}
	if len(v.AutoSystemRoutingTable) > 0 && v.AutoOutboundsInterface == nil {
		config.AutoOutboundsInterface = "auto"
	}

	switch strings.ToLower(strings.TrimSpace(v.ICMPMode)) {
	case "", "fake":
		config.IcmpMode = tun.IcmpMode_FAKE
	case "probe":
		config.IcmpMode = tun.IcmpMode_PROBE
	default:
		return nil, errors.New("unknown TUN ICMP mode: ", v.ICMPMode)
	}

	if config.Name == "" {
		config.Name = "xray0"
	}
	if config.MTU == 0 {
		config.MTU = 1500
	}
	return config, nil
}
