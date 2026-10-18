package anytls

import "github.com/xtls/xray-core/transport/internet"

const (
	tlsSecurityType     = "xray.transport.internet.tls.Config"
	realitySecurityType = "xray.transport.internet.reality.Config"
)

func hasRequiredStreamSecurity(config *internet.MemoryStreamConfig) bool {
	if config == nil {
		return false
	}
	return config.SecurityType == tlsSecurityType || config.SecurityType == realitySecurityType
}
