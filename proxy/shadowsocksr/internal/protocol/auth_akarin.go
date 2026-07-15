package protocol

import (
	"bytes"

	"github.com/xtls/xray-core/proxy/shadowsocksr/internal/tools"
)

func init() {
	register("auth_akarin_rand", NewAuthAkarinRand)
	register("auth_akarin_spec_a", NewAuthAkarinSpecA)
}

func newAuthAkarin(name string, spec bool) IProtocol {
	return &authChainA{
		salt: name, hmac: tools.HmacMD5, hashDigest: tools.SHA1Sum,
		rnd: authChainAGetRandLen, akarin: true, akarinSpec: spec,
		sendTCPMSS: 2000, recvTCPMSS: 2000,
		recvInfo: recvInfo{recvID: 1, buffer: new(bytes.Buffer)},
	}
}

func NewAuthAkarinRand() IProtocol  { return newAuthAkarin("auth_akarin_rand", false) }
func NewAuthAkarinSpecA() IProtocol { return newAuthAkarin("auth_akarin_spec_a", true) }
