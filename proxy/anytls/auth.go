package anytls

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"

	"github.com/xtls/xray-core/common/protocol"
)

const AuthPrefaceSize = 32

func WriteAuthPreface(w io.Writer, account *MemoryAccount, paddingLen ...int) error {
	if account == nil {
		return errors.New("anytls: missing account")
	}
	n := 0
	if len(paddingLen) > 0 {
		n = paddingLen[0]
	}
	if n < 0 || n > maxFrameData {
		return ErrMalformedFrame
	}
	b := make([]byte, 34+n)
	copy(b, account.Key[:])
	binary.BigEndian.PutUint16(b[32:34], uint16(n))
	if n > 0 {
		if _, e := rand.Read(b[34:]); e != nil {
			return e
		}
	}
	return writeAll(w, b)
}

func ReadAuthPreface(r io.Reader, validator *Validator) (*protocol.MemoryUser, error) {
	var h [34]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return nil, e
	}
	n := int(binary.BigEndian.Uint16(h[32:]))
	if n > 0 {
		if _, e := io.CopyN(io.Discard, r, int64(n)); e != nil {
			return nil, e
		}
	}
	u := validator.GetUserByKey(h[:32])
	if u == nil || subtle.ConstantTimeCompare(h[:32], u.Account.(*MemoryAccount).Key[:]) != 1 {
		return nil, errors.New("anytls: invalid user")
	}
	return u, nil
}
