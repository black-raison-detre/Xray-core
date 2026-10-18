package protocol

import (
	"bytes"
	"sort"

	"github.com/xtls/xray-core/proxy/shadowsocksr/internal/tools"
)

func init() {
	register("auth_chain_c", NewAuthChainC)
	register("auth_chain_d", NewAuthChainD)
	register("auth_chain_e", NewAuthChainE)
	register("auth_chain_f", NewAuthChainF)
}

func newAuthChainVariant(name string, rnd rndMethod) IProtocol {
	return &authChainA{
		salt: name, hmac: tools.HmacMD5, hashDigest: tools.SHA1Sum, rnd: rnd,
		recvInfo: recvInfo{recvID: 1, buffer: new(bytes.Buffer)},
	}
}

func NewAuthChainC() IProtocol { return newAuthChainVariant("auth_chain_c", authChainCGetRandLen) }
func NewAuthChainD() IProtocol { return newAuthChainVariant("auth_chain_d", authChainDGetRandLen) }
func NewAuthChainE() IProtocol { return newAuthChainVariant("auth_chain_e", authChainEGetRandLen) }
func NewAuthChainF() IProtocol { return newAuthChainVariant("auth_chain_f", authChainEGetRandLen) }

func authChainCGetRandLen(dataLength int, random *tools.Shift128plusContext, lastHash []byte, sizes, _ []int, overhead int) int {
	otherSize := dataLength + overhead
	random.InitFromBinDatalen(lastHash[:16], dataLength)
	if len(sizes) == 0 || otherSize >= sizes[len(sizes)-1] {
		return authChainAFallbackRandLen(otherSize, random)
	}
	pos := sort.Search(len(sizes), func(i int) bool { return sizes[i] >= otherSize })
	finalPos := pos + int(random.Next()%uint64(len(sizes)-pos))
	return sizes[finalPos] - otherSize
}

func authChainDGetRandLen(dataLength int, random *tools.Shift128plusContext, lastHash []byte, sizes, _ []int, overhead int) int {
	otherSize := dataLength + overhead
	if len(sizes) == 0 || otherSize >= sizes[len(sizes)-1] {
		return 0
	}
	random.InitFromBinDatalen(lastHash[:16], dataLength)
	pos := sort.Search(len(sizes), func(i int) bool { return sizes[i] >= otherSize })
	return sizes[pos+int(random.Next()%uint64(len(sizes)-pos))] - otherSize
}

func authChainEGetRandLen(dataLength int, random *tools.Shift128plusContext, lastHash []byte, sizes, _ []int, overhead int) int {
	random.InitFromBinDatalen(lastHash[:16], dataLength)
	otherSize := dataLength + overhead
	if len(sizes) == 0 || otherSize >= sizes[len(sizes)-1] {
		return 0
	}
	pos := sort.Search(len(sizes), func(i int) bool { return sizes[i] >= otherSize })
	return sizes[pos] - otherSize
}

func authChainAFallbackRandLen(dataLength int, random *tools.Shift128plusContext) int {
	if dataLength >= 1440 {
		return 0
	}
	if dataLength > 1300 {
		return int(random.Next() % 31)
	}
	if dataLength > 900 {
		return int(random.Next() % 127)
	}
	if dataLength > 400 {
		return int(random.Next() % 521)
	}
	return int(random.Next() % 1021)
}
