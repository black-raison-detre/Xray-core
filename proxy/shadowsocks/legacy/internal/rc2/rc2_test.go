// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license in LICENSE.
package rc2

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestRFC2268Vectors(t *testing.T) {
	vectors := []struct {
		key, plain, cipher string
		bits               int
	}{
		{"0000000000000000", "0000000000000000", "ebb773f993278eff", 63},
		{"ffffffffffffffff", "ffffffffffffffff", "278b27e42e2f0d49", 64},
		{"88bca90e90875a7f0f79c384627bafb2", "0000000000000000", "2269552ab0f85ca6", 128},
	}
	for _, vector := range vectors {
		key, _ := hex.DecodeString(vector.key)
		plain, _ := hex.DecodeString(vector.plain)
		want, _ := hex.DecodeString(vector.cipher)
		block, err := New(key, vector.bits)
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
}
