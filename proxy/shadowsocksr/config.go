package shadowsocksr

import (
	"bytes"
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/shadowsocks/legacy"
)

var protocolNames = map[string]struct{}{
	"origin": {}, "auth_sha1": {}, "auth_sha1_v2": {}, "auth_sha1_v4": {},
	"auth_aes128_md5": {}, "auth_aes128_sha1": {},
	"auth_chain_a": {}, "auth_chain_b": {}, "auth_chain_c": {}, "auth_chain_d": {},
	"auth_chain_e": {}, "auth_chain_f": {},
	"auth_akarin_rand": {}, "auth_akarin_spec_a": {},
}

var obfsNames = map[string]struct{}{
	"plain": {}, "http_simple": {}, "http_post": {}, "tls1.2_ticket_auth": {},
}

func normalizeName(name string) string { return strings.ToLower(strings.TrimSpace(name)) }

func ValidateNames(method, protocolName, obfsName string) error {
	if _, ok := legacy.Lookup(normalizeName(method)); !ok {
		return fmt.Errorf("unsupported ShadowsocksR method %q", strings.TrimSpace(method))
	}
	if _, ok := protocolNames[normalizeName(protocolName)]; !ok {
		return fmt.Errorf("unsupported ShadowsocksR protocol %q", strings.TrimSpace(protocolName))
	}
	if _, ok := obfsNames[normalizeName(obfsName)]; !ok {
		return fmt.Errorf("unsupported ShadowsocksR obfs %q", strings.TrimSpace(obfsName))
	}
	return nil
}

type MemoryAccount struct {
	Cipher        *legacy.Cipher
	Password      string
	Method        string
	Protocol      string
	ProtocolParam []byte
	Obfs          string
	ObfsParam     []byte
}

func (a *MemoryAccount) Equals(other protocol.Account) bool {
	b, ok := other.(*MemoryAccount)
	return ok && a.Method == b.Method && a.Protocol == b.Protocol && a.Obfs == b.Obfs &&
		bytes.Equal(a.Cipher.Key(), b.Cipher.Key()) && bytes.Equal(a.ProtocolParam, b.ProtocolParam) &&
		bytes.Equal(a.ObfsParam, b.ObfsParam)
}

func (a *MemoryAccount) ToProto() proto.Message {
	return &Account{
		Password:      a.Password,
		Method:        a.Method,
		Protocol:      a.Protocol,
		ProtocolParam: append([]byte(nil), a.ProtocolParam...),
		Obfs:          a.Obfs,
		ObfsParam:     append([]byte(nil), a.ObfsParam...),
	}
}

func (a *Account) AsAccount() (protocol.Account, error) {
	method := normalizeName(a.Method)
	protocolName := normalizeName(a.Protocol)
	obfsName := normalizeName(a.Obfs)
	if a.Password == "" {
		return nil, fmt.Errorf("ShadowsocksR password is not specified")
	}
	if err := ValidateNames(method, protocolName, obfsName); err != nil {
		return nil, err
	}
	errors.PrintNonRemovalDeprecatedFeatureWarning(
		"ShadowsocksR with legacy cipher "+method+" (compatibility only; cryptographically obsolete)",
		"a modern outbound protocol",
	)
	cipherCore, err := legacy.New(method, a.Password)
	if err != nil {
		return nil, err
	}
	return &MemoryAccount{
		Cipher:        cipherCore,
		Password:      a.Password,
		Method:        method,
		Protocol:      protocolName,
		ProtocolParam: append([]byte(nil), a.ProtocolParam...),
		Obfs:          obfsName,
		ObfsParam:     append([]byte(nil), a.ObfsParam...),
	}, nil
}
