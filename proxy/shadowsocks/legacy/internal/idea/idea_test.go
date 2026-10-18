package idea

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestKnownAnswer(t *testing.T) {
	key, _ := hex.DecodeString("80000000000000000000000000000000")
	plain, _ := hex.DecodeString("0000000000000000")
	want, _ := hex.DecodeString("b1f5f7f87901370f")
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
