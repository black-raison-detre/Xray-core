package conf

import (
	"bytes"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/shadowsocksr"
)

type ShadowsocksRServerTarget struct {
	Address            *Address `json:"address"`
	Port               uint16   `json:"port"`
	Level              byte     `json:"level"`
	Email              string   `json:"email"`
	Method             string   `json:"method"`
	Password           string   `json:"password"`
	Protocol           string   `json:"protocol"`
	ProtocolParam      string   `json:"protocolParam"`
	ProtocolParamSnake string   `json:"protocol_param"`
	Obfs               string   `json:"obfs"`
	ObfsParam          string   `json:"obfsParam"`
	ObfsParamSnake     string   `json:"obfs_param"`
}

type ShadowsocksRClientConfig struct {
	Address            *Address                    `json:"address"`
	Port               uint16                      `json:"port"`
	Level              byte                        `json:"level"`
	Email              string                      `json:"email"`
	Method             string                      `json:"method"`
	Password           string                      `json:"password"`
	Protocol           string                      `json:"protocol"`
	ProtocolParam      string                      `json:"protocolParam"`
	ProtocolParamSnake string                      `json:"protocol_param"`
	Obfs               string                      `json:"obfs"`
	ObfsParam          string                      `json:"obfsParam"`
	ObfsParamSnake     string                      `json:"obfs_param"`
	Servers            []*ShadowsocksRServerTarget `json:"servers"`
}

func (v *ShadowsocksRClientConfig) hasDirectFields() bool {
	return v.Address != nil || v.Port != 0 || v.Level != 0 || v.Email != "" || v.Method != "" ||
		v.Password != "" || v.Protocol != "" || v.ProtocolParam != "" || v.ProtocolParamSnake != "" ||
		v.Obfs != "" || v.ObfsParam != "" || v.ObfsParamSnake != ""
}

func chooseSSRParam(camelName, camelValue, snakeName, snakeValue string) ([]byte, error) {
	if camelValue != "" && snakeValue != "" && camelValue != snakeValue {
		return nil, errors.New("ShadowsocksR settings: conflicting ", camelName, " and ", snakeName)
	}
	if camelValue != "" {
		return []byte(camelValue), nil
	}
	return []byte(snakeValue), nil
}

func (v *ShadowsocksRClientConfig) Build() (proto.Message, error) {
	direct := v.hasDirectFields()
	if direct && len(v.Servers) != 0 {
		return nil, errors.New(`ShadowsocksR settings: direct endpoint fields conflict with "servers"`)
	}
	var server *ShadowsocksRServerTarget
	if direct {
		server = &ShadowsocksRServerTarget{
			Address: v.Address, Port: v.Port, Level: v.Level, Email: v.Email,
			Method: v.Method, Password: v.Password, Protocol: v.Protocol,
			ProtocolParam: v.ProtocolParam, ProtocolParamSnake: v.ProtocolParamSnake,
			Obfs: v.Obfs, ObfsParam: v.ObfsParam, ObfsParamSnake: v.ObfsParamSnake,
		}
	} else {
		if len(v.Servers) != 1 {
			return nil, errors.New(`ShadowsocksR settings: "servers" must contain exactly one endpoint`)
		}
		server = v.Servers[0]
		if server == nil {
			return nil, errors.New("ShadowsocksR settings: server endpoint is null")
		}
	}
	if server.Address == nil {
		return nil, errors.New("ShadowsocksR server address is not set")
	}
	if server.Port == 0 {
		return nil, errors.New("invalid ShadowsocksR port")
	}
	method := strings.ToLower(strings.TrimSpace(server.Method))
	if method == "" {
		return nil, errors.New("ShadowsocksR method is not specified")
	}
	if server.Password == "" {
		return nil, errors.New("ShadowsocksR password is not specified")
	}
	protocolName := strings.ToLower(strings.TrimSpace(server.Protocol))
	if protocolName == "" {
		protocolName = "origin"
	}
	obfsName := strings.ToLower(strings.TrimSpace(server.Obfs))
	if obfsName == "" {
		obfsName = "plain"
	}
	protocolParam, err := chooseSSRParam("protocolParam", server.ProtocolParam, "protocol_param", server.ProtocolParamSnake)
	if err != nil {
		return nil, err
	}
	obfsParam, err := chooseSSRParam("obfsParam", server.ObfsParam, "obfs_param", server.ObfsParamSnake)
	if err != nil {
		return nil, err
	}
	if err := shadowsocksr.ValidateNames(method, protocolName, obfsName); err != nil {
		return nil, err
	}

	errors.PrintNonRemovalDeprecatedFeatureWarning(
		"ShadowsocksR with legacy cipher "+method+" (compatibility only; cryptographically obsolete)",
		"a modern outbound protocol",
	)
	account := &shadowsocksr.Account{
		Password: server.Password, Method: method, Protocol: protocolName,
		ProtocolParam: bytes.Clone(protocolParam), Obfs: obfsName, ObfsParam: bytes.Clone(obfsParam),
	}
	return &shadowsocksr.ClientConfig{Server: &protocol.ServerEndpoint{
		Address: server.Address.Build(), Port: uint32(server.Port),
		User: &protocol.User{Level: uint32(server.Level), Email: server.Email, Account: serial.ToTypedMessage(account)},
	}}, nil
}
