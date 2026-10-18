// Package anytls implements the native AnyTLS wire protocol.
package anytls

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"

	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common/protocol"
)

type MemoryAccount struct {
	Password string
	Key      [sha256.Size]byte
}

func NewMemoryAccount(password string) *MemoryAccount {
	return &MemoryAccount{Password: password, Key: sha256.Sum256([]byte(password))}
}
func (a *Account) AsAccount() (protocol.Account, error) { return NewMemoryAccount(a.Password), nil }
func (a *MemoryAccount) Equals(other protocol.Account) bool {
	b, ok := other.(*MemoryAccount)
	return ok && subtle.ConstantTimeCompare(a.Key[:], b.Key[:]) == 1
}

func (a *MemoryAccount) ToProto() proto.Message { return &Account{Password: a.Password} }
func (a *MemoryAccount) ID() string             { return hex.EncodeToString(a.Key[:]) }
