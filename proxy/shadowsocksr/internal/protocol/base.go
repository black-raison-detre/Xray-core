package protocol

import (
	"strings"

	"github.com/xtls/xray-core/proxy/shadowsocksr/internal/ssr"
	"github.com/xtls/xray-core/proxy/shadowsocksr/internal/tools"
)

type creator func() IProtocol

var creatorMap = make(map[string]creator)

type (
	hmacMethod       func(key []byte, data []byte) []byte
	hashDigestMethod func(data []byte) []byte
	rndMethod        func(dataLength int, random *tools.Shift128plusContext, lastHash []byte, dataSizeList, dataSizeList2 []int, overhead int) int
)

type IProtocol interface {
	SetServerInfo(s *ssr.ServerInfo)
	GetServerInfo() *ssr.ServerInfo
	PreEncrypt(data []byte) ([]byte, error)
	PostDecrypt(data []byte) ([]byte, int, error)
	SetData(data interface{})
	GetData() interface{}
	GetOverhead() int
}

// UDPProtocol is implemented by protocols whose C client registry defines a
// datagram transform. Protocols without it leave UDP payloads unchanged.
type UDPProtocol interface {
	UDPPreEncrypt(data []byte) ([]byte, error)
	UDPPostDecrypt(data []byte) ([]byte, error)
}

type AuthData struct {
	clientID     []byte
	connectionID uint32
}

func register(name string, c creator) {
	creatorMap[name] = c
}

func NewProtocol(name string) IProtocol {
	c, ok := creatorMap[strings.ToLower(name)]
	if ok {
		return c()
	}
	return nil
}
