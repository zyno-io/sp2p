// SPDX-License-Identifier: MIT

package transfer

import (
	"github.com/klauspost/compress/zstd"
	"testing"
)

func FuzzBoundedZstd(f *testing.F) {
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd, 0x20, 3, 25, 0, 0, 97, 98, 99})
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd, 0xe0, 0, 0, 0, 0, 2, 0, 0, 0})
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 65536 {
			t.Skip()
		}
		decoder, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(MaxChunkSize), zstd.WithDecoderMaxWindow(MaxChunkSize), zstd.WithDecodeAllCapLimit(true))
		if err != nil {
			t.Fatal(err)
		}
		defer decoder.Close()
		data, err := decoder.DecodeAll(input, make([]byte, 0, MaxChunkSize))
		if err == nil && len(data) > MaxChunkSize {
			t.Fatalf("decoder exceeded budget: %d", len(data))
		}
	})
}
