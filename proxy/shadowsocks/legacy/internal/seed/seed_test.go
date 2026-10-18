package seed

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestKISAVector(t *testing.T) {
	key, _ := hex.DecodeString("00000000000000000000000000000000")
	plain, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	// KISA/RFC 4269 vector; also matches OpenSSL's SEED legacy provider.
	want, _ := hex.DecodeString("5ebac6e0054e166819aff1cc6d346cdb")
	block, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, BlockSize)
	block.Encrypt(got, plain)
	if !bytes.Equal(got, want) {
		t.Fatalf("encrypt = %x, want %x", got, want)
	}
	block.Decrypt(got, got)
	if !bytes.Equal(got, plain) {
		t.Fatalf("decrypt = %x, want %x", got, plain)
	}
}
