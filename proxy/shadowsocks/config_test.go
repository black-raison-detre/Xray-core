package shadowsocks_test

import (
	"crypto/rand"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/proxy/shadowsocks"
)

func TestHistoricalLegacyCipherNumbers(t *testing.T) {
	values := map[shadowsocks.CipherType]int32{
		shadowsocks.CipherType_AES_128_CFB:        1,
		shadowsocks.CipherType_AES_256_CFB:        2,
		shadowsocks.CipherType_CHACHA20:           3,
		shadowsocks.CipherType_CHACHA20_IETF:      4,
		shadowsocks.CipherType_AES_128_GCM:        5,
		shadowsocks.CipherType_AES_256_GCM:        6,
		shadowsocks.CipherType_CHACHA20_POLY1305:  7,
		shadowsocks.CipherType_XCHACHA20_POLY1305: 8,
	}
	for cipherType, want := range values {
		if int32(cipherType) != want {
			t.Fatalf("%v = %d, want %d", cipherType, cipherType, want)
		}
	}
}

func TestAEADCipherUDP(t *testing.T) {
	rawAccount := &shadowsocks.Account{
		CipherType: shadowsocks.CipherType_AES_128_GCM,
		Password:   "test",
	}
	account, err := rawAccount.AsAccount()
	common.Must(err)

	cipher := account.(*shadowsocks.MemoryAccount).Cipher

	key := make([]byte, cipher.KeySize())
	common.Must2(rand.Read(key))

	payload := make([]byte, 1024)
	common.Must2(rand.Read(payload))

	b1 := buf.New()
	common.Must2(b1.ReadFullFrom(rand.Reader, cipher.IVSize()))
	common.Must2(b1.Write(payload))
	common.Must(cipher.EncodePacket(key, b1))

	common.Must(cipher.DecodePacket(key, b1))
	if diff := cmp.Diff(b1.Bytes(), payload); diff != "" {
		t.Error(diff)
	}
}
