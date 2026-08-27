//go:build !routeros_gre

package conf

import "github.com/xtls/xray-core/common"

func init() {
	common.Must(inboundConfigLoader.cache.RegisterCreator("tun", func() interface{} { return new(TunConfig) }))
	noListenerInboundProtocols["tun"] = true
}
