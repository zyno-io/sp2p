// SPDX-License-Identifier: MIT

package transfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"testing"
)

func TestReceiverLegacyArchiveDeclaredSizeCompatibility(t *testing.T) {
	payload := bytes.Repeat([]byte("pax"), 512)
	sum := sha256.Sum256(payload)

	tests := []struct {
		name        string
		meta        Metadata
		allowLegacy bool
		maxBytes    uint64
		wantError   string
	}{
		{
			name:        "v2 folder archive accepts omitted PAX header bytes",
			meta:        Metadata{Name: "folder", Size: 512, IsFolder: true},
			allowLegacy: true,
		},
		{
			name:      "v3 folder archive retains exact declared size",
			meta:      Metadata{Name: "folder", Size: 512, IsFolder: true},
			wantError: "transfer exceeds declared size",
		},
		{
			name:        "v2 regular file retains exact declared size",
			meta:        Metadata{Name: "file", Size: 512},
			allowLegacy: true,
			wantError:   "transfer exceeds declared size",
		},
		{
			name:        "v2 folder archive retains local receive quota",
			meta:        Metadata{Name: "folder", Size: 512, IsFolder: true},
			allowLegacy: true,
			maxBytes:    uint64(len(payload) - 1),
			wantError:   "transfer exceeds receive limit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender, receiver := newMockFrameRWPair()
			defer sender.Close()
			defer receiver.Close()

			if err := WriteMetadata(sender, &tt.meta); err != nil {
				t.Fatal(err)
			}
			if err := WriteData(sender, payload); err != nil {
				t.Fatal(err)
			}
			if err := WriteDone(sender, &Done{
				TotalBytes: uint64(len(payload)),
				ChunkCount: 1,
				SHA256:     hex.EncodeToString(sum[:]),
			}); err != nil {
				t.Fatal(err)
			}
			if tt.wantError == "" {
				if err := WriteFinAck(sender); err != nil {
					t.Fatal(err)
				}
			}

			recv := NewReceiver(receiver)
			recv.AllowLegacyArchiveSizeMismatch = tt.allowLegacy
			recv.MaxBytes = tt.maxBytes
			var output bytes.Buffer
			_, err := recv.Receive(context.Background(), &output, nil)
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("error = %v, want containing %q", err, tt.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(output.Bytes(), payload) {
				t.Fatal("received payload differs")
			}
		})
	}
}

func TestReceiverLegacyArchiveCompatibilityRetainsFinalVerification(t *testing.T) {
	payload := []byte("legacy PAX bytes beyond the declared size")
	sum := sha256.Sum256(payload)
	validHash := hex.EncodeToString(sum[:])

	tests := []struct {
		name       string
		totalBytes uint64
		chunkCount uint64
		checksum   string
		wantError  string
	}{
		{
			name:       "byte count",
			totalBytes: uint64(len(payload) - 1),
			chunkCount: 1,
			checksum:   validHash,
			wantError:  "verification mismatch",
		},
		{
			name:       "chunk count",
			totalBytes: uint64(len(payload)),
			chunkCount: 2,
			checksum:   validHash,
			wantError:  "verification mismatch",
		},
		{
			name:       "checksum",
			totalBytes: uint64(len(payload)),
			chunkCount: 1,
			checksum:   strings.Repeat("0", sha256.Size*2),
			wantError:  "integrity check failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender, receiver := newMockFrameRWPair()
			defer sender.Close()
			defer receiver.Close()

			if err := WriteMetadata(sender, &Metadata{Name: "folder", Size: 1, IsFolder: true}); err != nil {
				t.Fatal(err)
			}
			if err := WriteData(sender, payload); err != nil {
				t.Fatal(err)
			}
			if err := WriteDone(sender, &Done{
				TotalBytes: tt.totalBytes,
				ChunkCount: tt.chunkCount,
				SHA256:     tt.checksum,
			}); err != nil {
				t.Fatal(err)
			}

			finalized := false
			recv := NewReceiver(receiver)
			recv.AllowLegacyArchiveSizeMismatch = true
			recv.Finalize = func() error {
				finalized = true
				return nil
			}
			_, err := recv.Receive(context.Background(), io.Discard, nil)
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantError)
			}
			if finalized {
				t.Fatal("invalid transfer was finalized")
			}
			msgType, _, err := sender.ReadFrame()
			if err != nil {
				t.Fatal(err)
			}
			if msgType != MsgError {
				t.Fatalf("response type = 0x%02x, want MsgError", msgType)
			}
		})
	}
}
