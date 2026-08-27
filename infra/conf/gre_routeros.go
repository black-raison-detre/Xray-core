//go:build routeros_gre

package conf

import (
	"net/netip"
	"strings"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/gre"
	"google.golang.org/protobuf/proto"
)

type GREConfig struct {
	LocalAddress        string   `json:"localAddress"`
	RemoteAddress       string   `json:"remoteAddress"`
	AllowedInnerSources []string `json:"allowedInnerSources"`
	MTU                 uint32   `json:"mtu"`
	UserLevel           uint32   `json:"userLevel"`
	ICMPMode            string   `json:"icmpMode"`
}

func (c *GREConfig) Build() (proto.Message, error) {
	local, err := parseGREAddress("localAddress", c.LocalAddress)
	if err != nil {
		return nil, err
	}
	remote, err := parseGREAddress("remoteAddress", c.RemoteAddress)
	if err != nil {
		return nil, err
	}
	if local == remote {
		return nil, errors.New("GRE localAddress and remoteAddress must differ")
	}
	if len(c.AllowedInnerSources) == 0 {
		return nil, errors.New("GRE allowedInnerSources must not be empty")
	}
	allowed := make([]string, 0, len(c.AllowedInnerSources))
	for _, value := range c.AllowedInnerSources {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil || !prefix.Addr().Is4() {
			return nil, errors.New("GRE allowedInnerSources must contain IPv4 CIDRs: ", value)
		}
		allowed = append(allowed, prefix.Masked().String())
	}
	mtu := c.MTU
	if mtu == 0 {
		mtu = 1400
	}
	if mtu < 576 || mtu > 1472 {
		return nil, errors.New("GRE mtu must be 576..1472")
	}
	config := &gre.Config{
		LocalAddress:        local.String(),
		RemoteAddress:       remote.String(),
		AllowedInnerSources: allowed,
		Mtu:                 mtu,
		UserLevel:           c.UserLevel,
	}
	switch strings.ToLower(strings.TrimSpace(c.ICMPMode)) {
	case "", "fake":
		config.IcmpMode = gre.IcmpMode_FAKE
	case "probe":
		config.IcmpMode = gre.IcmpMode_PROBE
	default:
		return nil, errors.New("unknown GRE ICMP mode: ", c.ICMPMode)
	}
	return config, nil
}

func parseGREAddress(field, value string) (netip.Addr, error) {
	address, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || !address.Is4() || !address.IsGlobalUnicast() {
		return netip.Addr{}, errors.New("GRE ", field, " must be a unicast IPv4 address")
	}
	return address, nil
}

func init() {
	common.Must(inboundConfigLoader.cache.RegisterCreator("gre", func() interface{} { return new(GREConfig) }))
	noListenerInboundProtocols["gre"] = true
	strictPseudoInbounds["gre"] = true
}
