// SPDX-License-Identifier: MIT

package transfer

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func TestCompressedSendReceive(t *testing.T) {
	// Two pipes for bidirectional communication.
	sr, sw := io.Pipe() // sender → receiver
	rr, rw := io.Pipe() // receiver → sender

	fileData := bytes.Repeat([]byte("compressible test data "), 5000) // ~115KB
	meta := &Metadata{
		Name: "test.txt",
		Size: uint64(len(fileData)),
		Type: "text/plain",
	}

	errCh := make(chan error, 2)
	var receivedMeta *Metadata
	var receivedData bytes.Buffer

	// Receiver goroutine.
	go func() {
		frw := &PlaintextFrameRW{RW: &duplexRW{r: sr, w: rw}}
		recv := NewReceiver(frw)
		var err error
		receivedMeta, err = recv.Receive(context.Background(), &receivedData, nil)
		errCh <- err
	}()

	// Sender with compression enabled.
	senderFrw := &PlaintextFrameRW{RW: &duplexRW{r: rr, w: sw}}
	sender := NewSender(senderFrw, meta)
	if err := sender.SetCompression(3); err != nil {
		t.Fatal(err)
	}
	errCh <- sender.Send(context.Background(), bytes.NewReader(fileData), nil)

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}

	if receivedMeta.Name != meta.Name {
		t.Fatalf("name mismatch: %s != %s", receivedMeta.Name, meta.Name)
	}
	if receivedMeta.Compression != "zstd" {
		t.Fatalf("expected compression 'zstd', got '%s'", receivedMeta.Compression)
	}
	if !bytes.Equal(receivedData.Bytes(), fileData) {
		t.Fatalf("data mismatch: got %d bytes, expected %d", receivedData.Len(), len(fileData))
	}
}

func TestCompressedSendReceiveIncompressible(t *testing.T) {
	// Two pipes for bidirectional communication.
	sr, sw := io.Pipe()
	rr, rw := io.Pipe()

	// Random data is incompressible.
	fileData := make([]byte, 100*1024)
	if _, err := rand.Read(fileData); err != nil {
		t.Fatal(err)
	}
	meta := &Metadata{
		Name: "random.bin",
		Size: uint64(len(fileData)),
		Type: "application/octet-stream",
	}

	errCh := make(chan error, 2)
	var receivedData bytes.Buffer

	go func() {
		frw := &PlaintextFrameRW{RW: &duplexRW{r: sr, w: rw}}
		recv := NewReceiver(frw)
		_, err := recv.Receive(context.Background(), &receivedData, nil)
		errCh <- err
	}()

	senderFrw := &PlaintextFrameRW{RW: &duplexRW{r: rr, w: sw}}
	sender := NewSender(senderFrw, meta)
	if err := sender.SetCompression(3); err != nil {
		t.Fatal(err)
	}
	errCh <- sender.Send(context.Background(), bytes.NewReader(fileData), nil)

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}

	if !bytes.Equal(receivedData.Bytes(), fileData) {
		t.Fatalf("data mismatch: got %d bytes, expected %d", receivedData.Len(), len(fileData))
	}
}

func TestCompressionLevels(t *testing.T) {
	for _, level := range []int{0, 1, 3, 6, 9} {
		t.Run(fmt.Sprintf("level_%d", level), func(t *testing.T) {
			sr, sw := io.Pipe()
			rr, rw := io.Pipe()

			fileData := bytes.Repeat([]byte("hello "), 1000)
			meta := &Metadata{
				Name: "test.txt",
				Size: uint64(len(fileData)),
				Type: "text/plain",
			}

			errCh := make(chan error, 2)
			var receivedData bytes.Buffer

			go func() {
				frw := &PlaintextFrameRW{RW: &duplexRW{r: sr, w: rw}}
				recv := NewReceiver(frw)
				_, err := recv.Receive(context.Background(), &receivedData, nil)
				errCh <- err
			}()

			senderFrw := &PlaintextFrameRW{RW: &duplexRW{r: rr, w: sw}}
			sender := NewSender(senderFrw, meta)
			if err := sender.SetCompression(level); err != nil {
				t.Fatal(err)
			}
			errCh <- sender.Send(context.Background(), bytes.NewReader(fileData), nil)

			for i := 0; i < 2; i++ {
				if err := <-errCh; err != nil {
					t.Fatal(err)
				}
			}

			if !bytes.Equal(receivedData.Bytes(), fileData) {
				t.Fatalf("level %d: data mismatch", level)
			}
		})
	}
}

func TestCompressionMetadataJSON(t *testing.T) {
	// With compression set.
	meta := Metadata{Name: "test.txt", Size: 100, Compression: "zstd"}
	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"compression":"zstd"`)) {
		t.Fatalf("expected compression field in JSON: %s", data)
	}

	var decoded Metadata
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Compression != "zstd" {
		t.Fatalf("expected 'zstd', got '%s'", decoded.Compression)
	}

	// Without compression (omitempty).
	meta2 := Metadata{Name: "test.txt", Size: 100}
	data2, err := json.Marshal(meta2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data2, []byte(`compression`)) {
		t.Fatalf("compression field should be omitted: %s", data2)
	}
}

func TestSetCompressionZeroDisables(t *testing.T) {
	sr, sw := io.Pipe()
	rr, rw := io.Pipe()

	fileData := bytes.Repeat([]byte("test "), 100)
	meta := &Metadata{
		Name: "test.txt",
		Size: uint64(len(fileData)),
		Type: "text/plain",
	}

	errCh := make(chan error, 2)
	var receivedMeta *Metadata
	var receivedData bytes.Buffer

	go func() {
		frw := &PlaintextFrameRW{RW: &duplexRW{r: sr, w: rw}}
		recv := NewReceiver(frw)
		var err error
		receivedMeta, err = recv.Receive(context.Background(), &receivedData, nil)
		errCh <- err
	}()

	senderFrw := &PlaintextFrameRW{RW: &duplexRW{r: rr, w: sw}}
	sender := NewSender(senderFrw, meta)
	if err := sender.SetCompression(0); err != nil {
		t.Fatal(err)
	}
	errCh <- sender.Send(context.Background(), bytes.NewReader(fileData), nil)

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}

	if receivedMeta.Compression != "" {
		t.Fatalf("expected no compression, got '%s'", receivedMeta.Compression)
	}
	if !bytes.Equal(receivedData.Bytes(), fileData) {
		t.Fatalf("data mismatch")
	}
}

func TestReceiverRejectsUnsupportedCompression(t *testing.T) {
	var buf bytes.Buffer
	frw := &PlaintextFrameRW{RW: &buf}

	meta := &Metadata{Name: "test.txt", Size: 10, Compression: "lz4"}
	if err := WriteMetadata(frw, meta); err != nil {
		t.Fatal(err)
	}

	readFrw := &PlaintextFrameRW{RW: &buf}
	recv := NewReceiver(readFrw)
	_, err := recv.Receive(context.Background(), &bytes.Buffer{}, nil)
	if err == nil {
		t.Fatal("expected error for unsupported compression")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("unsupported compression")) {
		t.Fatalf("expected 'unsupported compression' error, got: %s", err)
	}
}

func TestCompressedProgressReportsUncompressedBytes(t *testing.T) {
	sr, sw := io.Pipe()
	rr, rw := io.Pipe()

	fileData := bytes.Repeat([]byte("progress test data "), 5000) // ~95KB
	meta := &Metadata{
		Name: "test.txt",
		Size: uint64(len(fileData)),
		Type: "text/plain",
	}

	errCh := make(chan error, 2)

	var recvProgressValues []uint64
	go func() {
		frw := &PlaintextFrameRW{RW: &duplexRW{r: sr, w: rw}}
		recv := NewReceiver(frw)
		_, err := recv.Receive(context.Background(), io.Discard, func(bytesRecv uint64) {
			recvProgressValues = append(recvProgressValues, bytesRecv)
		})
		errCh <- err
	}()

	var sendProgressValues []uint64
	senderFrw := &PlaintextFrameRW{RW: &duplexRW{r: rr, w: sw}}
	sender := NewSender(senderFrw, meta)
	if err := sender.SetCompression(3); err != nil {
		t.Fatal(err)
	}
	errCh <- sender.Send(context.Background(), bytes.NewReader(fileData), func(bytesSent uint64) {
		sendProgressValues = append(sendProgressValues, bytesSent)
	})

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}

	// Progress should be monotonically increasing.
	for i := 1; i < len(sendProgressValues); i++ {
		if sendProgressValues[i] <= sendProgressValues[i-1] {
			t.Fatalf("sender progress not monotonic at index %d: %d <= %d",
				i, sendProgressValues[i], sendProgressValues[i-1])
		}
	}

	// Final sender progress should equal uncompressed size.
	totalSend, _ := sender.Stats()
	if totalSend != uint64(len(fileData)) {
		t.Fatalf("sender stats: expected %d bytes, got %d", len(fileData), totalSend)
	}

	// Final receiver progress should also equal uncompressed size.
	if len(recvProgressValues) == 0 {
		t.Fatal("no receiver progress callbacks")
	}
	lastRecv := recvProgressValues[len(recvProgressValues)-1]
	if lastRecv != uint64(len(fileData)) {
		t.Fatalf("receiver final progress: expected %d, got %d", len(fileData), lastRecv)
	}
}

func TestCompressedMultiChunk(t *testing.T) {
	sr, sw := io.Pipe()
	rr, rw := io.Pipe()

	// Data larger than MaxChunkSize (64KB) to ensure multiple chunks.
	fileData := bytes.Repeat([]byte("multi-chunk compressed data "), 10000) // ~280KB
	meta := &Metadata{
		Name: "large.txt",
		Size: uint64(len(fileData)),
		Type: "text/plain",
	}

	errCh := make(chan error, 2)
	var receivedData bytes.Buffer

	go func() {
		frw := &PlaintextFrameRW{RW: &duplexRW{r: sr, w: rw}}
		recv := NewReceiver(frw)
		_, err := recv.Receive(context.Background(), &receivedData, nil)
		errCh <- err
	}()

	senderFrw := &PlaintextFrameRW{RW: &duplexRW{r: rr, w: sw}}
	sender := NewSender(senderFrw, meta)
	if err := sender.SetCompression(3); err != nil {
		t.Fatal(err)
	}
	errCh <- sender.Send(context.Background(), bytes.NewReader(fileData), nil)

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}

	_, chunkCount := sender.Stats()
	if chunkCount <= 1 {
		t.Fatalf("expected multiple chunks, got %d", chunkCount)
	}
	if !bytes.Equal(receivedData.Bytes(), fileData) {
		t.Fatalf("data mismatch: got %d bytes, expected %d", receivedData.Len(), len(fileData))
	}
}

func TestDecompressionBoundCheck(t *testing.T) {
	// Craft a compressed data frame that decompresses to more than MaxChunkSize.
	// This tests the decompression bomb protection.
	var buf bytes.Buffer
	frw := &PlaintextFrameRW{RW: &buf}

	// Write metadata indicating zstd compression.
	meta := &Metadata{Name: "test.bin", Size: 0, Compression: "zstd"}
	if err := WriteMetadata(frw, meta); err != nil {
		t.Fatal(err)
	}

	// Create a compressed chunk that expands beyond MaxChunkSize.
	// Highly compressible data (all zeros) compresses to a tiny payload.
	bigData := make([]byte, MaxChunkSize+1)
	enc, _ := zstd.NewWriter(nil)
	compressed := enc.EncodeAll(bigData, nil)

	// Write the compressed data as a single frame.
	if err := WriteData(frw, compressed); err != nil {
		t.Fatal(err)
	}

	// Receiver should reject this chunk.
	readFrw := &PlaintextFrameRW{RW: &buf}
	recv := NewReceiver(readFrw)
	_, err := recv.Receive(context.Background(), io.Discard, nil)
	if err == nil {
		t.Fatal("expected error for oversized decompressed chunk")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("decompressed chunk too large")) {
		t.Fatalf("expected 'decompressed chunk too large' error, got: %s", err)
	}
}
