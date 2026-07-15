package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/xtls/xray-core/proxy/shadowsocksr/internal/ssr"
	"github.com/xtls/xray-core/proxy/shadowsocksr/internal/tools"
)

func init() {
	register("auth_sha1", NewAuthSHA1)
	register("auth_sha1_v2", NewAuthSHA1v2)
}

type authSHA1Legacy struct {
	ssr.ServerInfo
	data          *AuthData
	variant       int
	hasSentHeader bool
	buffer        bytes.Buffer
}

func NewAuthSHA1() IProtocol                              { return &authSHA1Legacy{variant: 1} }
func NewAuthSHA1v2() IProtocol                            { return &authSHA1Legacy{variant: 2} }
func (a *authSHA1Legacy) SetServerInfo(s *ssr.ServerInfo) { a.ServerInfo = *s }
func (a *authSHA1Legacy) GetServerInfo() *ssr.ServerInfo  { return &a.ServerInfo }
func (a *authSHA1Legacy) SetData(v interface{}) {
	if d, ok := v.(*AuthData); ok {
		a.data = d
	}
}

func (a *authSHA1Legacy) GetData() interface{} {
	if a.data == nil {
		a.data = &AuthData{}
	}
	return a.data
}
func (a *authSHA1Legacy) GetOverhead() int { return 7 }

func (a *authSHA1Legacy) randLen(dataLen int, auth bool) int {
	if a.variant == 1 {
		if auth {
			return ssr.RandomInt(&a.ServerInfo, 128) + 1
		}
		return ssr.RandomInt(&a.ServerInfo, 16) + 1
	}
	if dataLen > 1300 {
		return 1
	}
	if dataLen > 400 {
		return ssr.RandomInt(&a.ServerInfo, 128) + 1
	}
	return ssr.RandomInt(&a.ServerInfo, 1024) + 1
}

func (a *authSHA1Legacy) packData(data []byte) []byte {
	randomLen := a.randLen(len(data), false)
	outLen := randomLen + len(data) + 6
	out := make([]byte, outLen)
	binary.BigEndian.PutUint16(out[:2], uint16(outLen))
	if a.variant == 1 || randomLen < 128 {
		out[2] = byte(randomLen)
	} else {
		out[2] = 0xff
		binary.BigEndian.PutUint16(out[3:5], uint16(randomLen))
	}
	randomStart := 3
	if a.variant == 2 && randomLen >= 128 {
		randomStart = 5
	}
	ssr.ReadRandom(&a.ServerInfo, out[randomStart:2+randomLen])
	copy(out[2+randomLen:], data)
	binary.LittleEndian.PutUint32(out[outLen-4:], ssr.CalcAdler32(out[:outLen-4]))
	return out
}

func (a *authSHA1Legacy) packAuthData(data []byte) []byte {
	randomLen := a.randLen(len(data), true)
	dataOffset := randomLen + 6
	outLen := dataOffset + len(data) + 12 + ssr.ObfsHMACSHA1Len
	out := make([]byte, outLen)
	crcInput := a.Key
	if a.variant == 2 {
		crcInput = append([]byte("auth_sha1_v2"), a.Key...)
	}
	binary.LittleEndian.PutUint32(out[:4], ssr.CalcCRC32(crcInput, len(crcInput), 0xffffffff))
	binary.BigEndian.PutUint16(out[4:6], uint16(outLen))
	if a.variant == 1 || randomLen < 128 {
		out[6] = byte(randomLen)
	} else {
		out[6] = 0xff
		binary.BigEndian.PutUint16(out[7:9], uint16(randomLen))
	}
	randomStart := 7
	if a.variant == 2 && randomLen >= 128 {
		randomStart = 9
	}
	ssr.ReadRandom(&a.ServerInfo, out[randomStart:dataOffset])
	a.data.connectionID++
	if a.data.connectionID > 0xff000000 || len(a.data.clientID) < 8 {
		a.data.clientID = make([]byte, 8)
		ssr.ReadRandom(&a.ServerInfo, a.data.clientID)
		var seed [4]byte
		ssr.ReadRandom(&a.ServerInfo, seed[:])
		a.data.connectionID = binary.LittleEndian.Uint32(seed[:]) & 0xffffff
	}
	if a.variant == 1 {
		binary.LittleEndian.PutUint32(out[dataOffset:dataOffset+4], uint32(ssr.NowUnix(&a.ServerInfo)))
		copy(out[dataOffset+4:dataOffset+8], a.data.clientID[:4])
	} else {
		copy(out[dataOffset:dataOffset+8], a.data.clientID[:8])
	}
	binary.LittleEndian.PutUint32(out[dataOffset+8:dataOffset+12], a.data.connectionID)
	copy(out[dataOffset+12:], data)
	key := append(append([]byte(nil), a.IV...), a.Key...)
	copy(out[outLen-ssr.ObfsHMACSHA1Len:], tools.HmacSHA1(key, out[:outLen-ssr.ObfsHMACSHA1Len])[:ssr.ObfsHMACSHA1Len])
	return out
}

func (a *authSHA1Legacy) PreEncrypt(data []byte) ([]byte, error) {
	a.buffer.Reset()
	if len(data) > 0 && !a.hasSentHeader {
		n := ssr.GetHeadSize(data, 30)
		if n > len(data) {
			n = len(data)
		}
		a.buffer.Write(a.packAuthData(data[:n]))
		data = data[n:]
		a.hasSentHeader = true
	}
	for len(data) > 4096 {
		a.buffer.Write(a.packData(data[:4096]))
		data = data[4096:]
	}
	if len(data) > 0 {
		a.buffer.Write(a.packData(data))
	}
	return append([]byte(nil), a.buffer.Bytes()...), nil
}

func (a *authSHA1Legacy) PostDecrypt(data []byte) ([]byte, int, error) {
	a.buffer.Reset()
	consumed := 0
	for len(data) > 2 {
		length := int(binary.BigEndian.Uint16(data[:2]))
		if length >= 8192 || length < 7 {
			return nil, 0, fmt.Errorf("auth_sha1 invalid frame length %d", length)
		}
		if length > len(data) {
			break
		}
		if !ssr.CheckAdler32(data, length) {
			return nil, 0, fmt.Errorf("auth_sha1 invalid adler32")
		}
		pos := int(data[2])
		if a.variant == 1 || pos < 255 {
			pos += 2
		} else {
			if length < 5 {
				return nil, 0, fmt.Errorf("auth_sha1_v2 truncated padding")
			}
			pos = int(binary.BigEndian.Uint16(data[3:5])) + 2
		}
		if pos > length-4 {
			return nil, 0, fmt.Errorf("auth_sha1 padding exceeds frame")
		}
		a.buffer.Write(data[pos : length-4])
		consumed += length
		data = data[length:]
	}
	return append([]byte(nil), a.buffer.Bytes()...), consumed, nil
}
