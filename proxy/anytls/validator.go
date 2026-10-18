package anytls

import (
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/protocol"
)

// Validator permits live user updates without racing active connections.
type Validator struct {
	users  sync.Map
	emails sync.Map
}

func (v *Validator) Add(user *protocol.MemoryUser) error {
	a, ok := user.Account.(*MemoryAccount)
	if !ok {
		return ErrMalformedFrame
	}
	key := string(a.Key[:])
	if _, loaded := v.users.LoadOrStore(key, user); loaded {
		return ErrMalformedFrame
	}
	if user.Email != "" {
		if _, loaded := v.emails.LoadOrStore(strings.ToLower(user.Email), user); loaded {
			v.users.Delete(key)
			return ErrMalformedFrame
		}
	}
	return nil
}

func (v *Validator) Del(email string) bool {
	u, ok := v.emails.LoadAndDelete(strings.ToLower(email))
	if !ok {
		return false
	}
	a, ok := u.(*protocol.MemoryUser).Account.(*MemoryAccount)
	if ok {
		v.users.Delete(string(a.Key[:]))
	}
	return true
}

func (v *Validator) GetByEmail(email string) *protocol.MemoryUser {
	if u, ok := v.emails.Load(strings.ToLower(email)); ok {
		return u.(*protocol.MemoryUser)
	}
	return nil
}

func (v *Validator) GetAll() []*protocol.MemoryUser {
	out := make([]*protocol.MemoryUser, 0)
	v.users.Range(func(_, u any) bool { out = append(out, u.(*protocol.MemoryUser)); return true })
	return out
}

func (v *Validator) GetCount() int64 {
	var n int64
	v.users.Range(func(_, _ any) bool { n++; return true })
	return n
}

func (v *Validator) Get(key []byte) *MemoryAccount {
	if len(key) != AuthPrefaceSize {
		return nil
	}
	if u, ok := v.users.Load(string(key)); ok {
		return u.(*protocol.MemoryUser).Account.(*MemoryAccount)
	}
	return nil
}

// GetUser preserves the complete authenticated user for inbound accounting.
func (v *Validator) GetUserByKey(key []byte) *protocol.MemoryUser {
	if len(key) != AuthPrefaceSize {
		return nil
	}
	if u, ok := v.users.Load(string(key)); ok {
		return u.(*protocol.MemoryUser)
	}
	return nil
}
