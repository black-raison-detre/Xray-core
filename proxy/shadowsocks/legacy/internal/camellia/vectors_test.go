// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be found in LICENSE.
package camellia

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestRFC3713Vectors(t *testing.T) {
	vectors := [][3]string{
		{"0123456789abcdeffedcba9876543210", "0123456789abcdeffedcba9876543210", "67673138549669730857065648eabe43"},
		{"0123456789abcdeffedcba98765432100011223344556677", "0123456789abcdeffedcba9876543210", "b4993401b3e996f84ee5cee7d79b09b9"},
		{"0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff", "0123456789abcdeffedcba9876543210", "9acc237dff16d76c20ef7c919e3a7509"},
	}
	for _, vector := range vectors {
		key, _ := hex.DecodeString(vector[0])
		plain, _ := hex.DecodeString(vector[1])
		want, _ := hex.DecodeString(vector[2])
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
}
