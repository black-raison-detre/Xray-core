package anytls

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/big"
	"strconv"
	"strings"
)

const (
	DefaultPaddingScheme = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000"
	paddingContinue      = -1
)

type paddingRange struct {
	min, max int
	cont     bool
}
type PaddingFactory struct {
	raw     []byte
	md5     string
	stop    uint32
	records map[uint32][]paddingRange
}

func NewPaddingFactory(raw []byte) (*PaddingFactory, error) {
	f := &PaddingFactory{raw: append([]byte(nil), raw...), records: make(map[uint32][]paddingRange)}
	s := md5.Sum(raw)
	f.md5 = hex.EncodeToString(s[:])
	seenStop := false
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p := strings.SplitN(line, "=", 2)
		if len(p) != 2 {
			return nil, errors.New("anytls: malformed padding scheme")
		}
		if p[0] == "stop" {
			n, e := strconv.ParseUint(p[1], 10, 32)
			if e != nil {
				return nil, ErrMalformedFrame
			}
			f.stop = uint32(n)
			seenStop = true
			continue
		}
		idx, e := strconv.ParseUint(p[0], 10, 32)
		if e != nil {
			return nil, ErrMalformedFrame
		}
		var ranges []paddingRange
		for _, token := range strings.Split(p[1], ",") {
			token = strings.TrimSpace(token)
			if token == "c" {
				ranges = append(ranges, paddingRange{cont: true})
				continue
			}
			lr := strings.SplitN(token, "-", 2)
			if len(lr) != 2 {
				return nil, ErrMalformedFrame
			}
			lo, e1 := strconv.Atoi(lr[0])
			hi, e2 := strconv.Atoi(lr[1])
			if e1 != nil || e2 != nil || lo <= 0 || hi <= 0 || lo > maxFrameData || hi > maxFrameData {
				return nil, ErrMalformedFrame
			}
			if lo > hi {
				lo, hi = hi, lo
			}
			ranges = append(ranges, paddingRange{min: lo, max: hi})
		}
		f.records[uint32(idx)] = ranges
	}
	if !seenStop {
		return nil, errors.New("anytls: padding scheme has no stop")
	}
	return f, nil
}

func DefaultPaddingFactory() *PaddingFactory {
	f, _ := NewPaddingFactory([]byte(DefaultPaddingScheme))
	return f
}
func (f *PaddingFactory) RawScheme() []byte { return append([]byte(nil), f.raw...) }
func (f *PaddingFactory) MD5() string       { return f.md5 }
func (f *PaddingFactory) Stop() uint32      { return f.stop }

// RecordSizes returns independently randomized plaintext record targets. A -1
// marks the documented conditional continuation point.
func (f *PaddingFactory) RecordSizes(packet uint32) []int {
	if packet >= f.stop {
		return nil
	}
	rs := f.records[packet]
	out := make([]int, 0, len(rs))
	for _, r := range rs {
		if r.cont {
			out = append(out, paddingContinue)
			continue
		}
		if r.min == r.max {
			out = append(out, r.min)
			continue
		}
		n, e := rand.Int(rand.Reader, big.NewInt(int64(r.max-r.min)))
		if e != nil {
			out = append(out, r.min)
		} else {
			out = append(out, r.min+int(n.Int64()))
		}
	}
	return out
}
