// SPDX-License-Identifier: MIT

package transfer

import (
	"crypto/rand"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func BenchmarkCompressionChunks(b *testing.B) {
	for _, random := range []bool{false, true} {
		name := "compressible"
		if random {
			name = "random"
		}
		data := make([]byte, MaxChunkSize)
		if random {
			if _, err := rand.Read(data); err != nil {
				b.Fatal(err)
			}
		}
		for _, parallel := range []bool{false, true} {
			mode := "serial"
			if parallel {
				mode = "parallel"
			}
			b.Run(name+"/"+mode, func(b *testing.B) {
				enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderConcurrency(4))
				if err != nil {
					b.Fatal(err)
				}
				defer enc.Close()
				b.SetBytes(MaxChunkSize)
				b.ReportAllocs()
				b.ResetTimer()
				if parallel {
					b.RunParallel(func(pb *testing.PB) {
						for pb.Next() {
							enc.EncodeAll(data, nil)
						}
					})
				} else {
					for i := 0; i < b.N; i++ {
						enc.EncodeAll(data, nil)
					}
				}
			})
		}
	}
}
