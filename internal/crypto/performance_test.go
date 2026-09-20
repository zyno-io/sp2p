// SPDX-License-Identifier: MIT

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

func BenchmarkDecryptOwnedPayload(b *testing.B) {
	block, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		b.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		b.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	sealed := aead.Seal(nil, nonce, make([]byte, 256*1024), nil)
	for _, inPlace := range []bool{false, true} {
		name := "separate"
		if inPlace {
			name = "in_place"
		}
		b.Run(name, func(b *testing.B) {
			b.SetBytes(256 * 1024)
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				payload := append([]byte(nil), sealed...)
				var dst []byte
				if inPlace {
					dst = payload[:0]
				}
				if _, err := aead.Open(dst, nonce, payload, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
