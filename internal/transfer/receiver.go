// SPDX-License-Identifier: MIT

package transfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"time"

	"github.com/klauspost/compress/zstd"
)

// Receiver receives files over a FrameReadWriter (encrypted or plaintext).
type Receiver struct {
	frw          FrameReadWriter
	idleTimeout  time.Duration
	deadliner    DeadlineSetter
	totalBytes   uint64
	chunkCount   uint64
	hash         hash.Hash
	decompressor *zstd.Decoder
	OnMetadata   func(*Metadata) // called after metadata is parsed, before data transfer
}

// NewReceiver creates a new transfer receiver.
func NewReceiver(frw FrameReadWriter) *Receiver {
	return &Receiver{frw: frw, hash: sha256.New()}
}

// SetIdleTimeout configures a per-operation idle timeout.
// The deadline is reset before each read/write operation.
func (recv *Receiver) SetIdleTimeout(d DeadlineSetter, timeout time.Duration) {
	recv.deadliner = d
	recv.idleTimeout = timeout
}

func (recv *Receiver) resetDeadline() {
	if recv.deadliner != nil && recv.idleTimeout > 0 {
		recv.deadliner.SetDeadline(time.Now().Add(recv.idleTimeout))
	}
}

func (recv *Receiver) clearDeadline() {
	if recv.deadliner != nil {
		recv.deadliner.SetDeadline(time.Time{})
	}
}

// Receive performs the full receive flow: metadata -> data chunks -> done -> send complete.
// Returns the metadata. The onProgress callback is called with cumulative bytes received.
// The context is used for cancellation — when ctx is cancelled, the underlying
// connection deadline is set to the past to unblock any pending I/O.
func (recv *Receiver) Receive(ctx context.Context, w io.Writer, onProgress func(bytesRecv uint64)) (*Metadata, error) {
	defer recv.clearDeadline()

	// Watch for context cancellation and force-expire the connection deadline
	// so that any blocked I/O returns immediately.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			if recv.deadliner != nil {
				recv.deadliner.SetDeadline(time.Now())
			}
		case <-done:
		}
	}()

	// Read metadata.
	recv.resetDeadline()
	msgType, data, err := recv.frw.ReadFrame()
	if err != nil {
		return nil, recv.wrapCtxErr(ctx, fmt.Errorf("reading metadata: %w", err))
	}
	if msgType != MsgMetadata {
		return nil, fmt.Errorf("expected metadata (0x%02x), got 0x%02x", MsgMetadata, msgType)
	}
	if len(data) > MaxControlSize {
		return nil, fmt.Errorf("metadata too large: %d bytes (max %d)", len(data), MaxControlSize)
	}
	var meta Metadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("parsing metadata: %w", err)
	}
	if recv.OnMetadata != nil {
		recv.OnMetadata(&meta)
	}

	// Initialize decompressor if sender indicated compression.
	if meta.Compression == "zstd" {
		dec, err := zstd.NewReader(nil)
		if err != nil {
			return nil, fmt.Errorf("creating zstd decoder: %w", err)
		}
		recv.decompressor = dec
		defer dec.Close()
	} else if meta.Compression != "" {
		return nil, fmt.Errorf("unsupported compression: %s", meta.Compression)
	}

	// Read data chunks until DONE.
	for {
		recv.resetDeadline()
		msgType, data, err = recv.frw.ReadFrame()
		if err != nil {
			return nil, recv.wrapCtxErr(ctx, fmt.Errorf("reading frame: %w", err))
		}

		switch msgType {
		case MsgData:
			// Decompress if compression is enabled.
			if recv.decompressor != nil {
				data, err = recv.decompressor.DecodeAll(data, nil)
				if err != nil {
					WriteError(recv.frw, "decompression failed: "+err.Error())
					return nil, fmt.Errorf("decompressing data: %w", err)
				}
				if len(data) > MaxChunkSize {
					WriteError(recv.frw, "decompressed chunk exceeds maximum size")
					return nil, fmt.Errorf("decompressed chunk too large: %d bytes (max %d)", len(data), MaxChunkSize)
				}
			}
			n, err := w.Write(data)
			if err != nil {
				WriteError(recv.frw, "write failed: "+err.Error())
				return nil, fmt.Errorf("writing data: %w", err)
			}
			if n < len(data) {
				WriteError(recv.frw, "short write")
				return nil, fmt.Errorf("short write: wrote %d of %d bytes", n, len(data))
			}
			recv.hash.Write(data)
			recv.totalBytes += uint64(n)
			recv.chunkCount++
			if onProgress != nil {
				onProgress(recv.totalBytes)
			}

		case MsgDone:
			if len(data) > MaxControlSize {
				return nil, fmt.Errorf("done message too large: %d bytes (max %d)", len(data), MaxControlSize)
			}
			var doneMsg Done
			if err := json.Unmarshal(data, &doneMsg); err != nil {
				return nil, fmt.Errorf("parsing done: %w", err)
			}

			// Verify counts.
			if doneMsg.TotalBytes != recv.totalBytes || doneMsg.ChunkCount != recv.chunkCount {
				errMsg := fmt.Sprintf("verification mismatch: expected %d bytes/%d chunks, got %d/%d",
					doneMsg.TotalBytes, doneMsg.ChunkCount, recv.totalBytes, recv.chunkCount)
				WriteError(recv.frw, errMsg)
				return nil, fmt.Errorf("%s", errMsg)
			}

			// Verify integrity checksum.
			checksum := hex.EncodeToString(recv.hash.Sum(nil))
			if doneMsg.SHA256 != checksum {
				errMsg := fmt.Sprintf("integrity check failed: sender SHA-256 %s, receiver SHA-256 %s", doneMsg.SHA256, checksum)
				WriteError(recv.frw, errMsg)
				return nil, fmt.Errorf("%s", errMsg)
			}

			// Send complete.
			recv.resetDeadline()
			if err := WriteComplete(recv.frw, &Complete{
				TotalBytes: recv.totalBytes,
				ChunkCount: recv.chunkCount,
				SHA256:     checksum,
			}); err != nil {
				return nil, recv.wrapCtxErr(ctx, fmt.Errorf("sending complete: %w", err))
			}
			// Wait for the sender's FinAck so we don't tear down the
			// connection before it reads our Complete message.
			recv.resetDeadline()
			recv.frw.ReadFrame() // best-effort, ignore errors
			return &meta, nil

		case MsgError:
			if len(data) > MaxControlSize {
				return nil, fmt.Errorf("error message too large: %d bytes", len(data))
			}
			var te TransferError
			if err := json.Unmarshal(data, &te); err != nil {
				return nil, fmt.Errorf("sender error (malformed): %s", string(data))
			}
			return nil, fmt.Errorf("sender error: %s", te.Message)

		default:
			return nil, fmt.Errorf("unexpected message type: 0x%02x", msgType)
		}
	}
}

// wrapCtxErr returns ctx.Err() if the context was cancelled, otherwise the original error.
// This provides a clear "context canceled" error instead of a confusing I/O timeout error
// when the user hits Ctrl+C.
func (recv *Receiver) wrapCtxErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// Stats returns the transfer statistics.
func (recv *Receiver) Stats() (totalBytes, chunkCount uint64) {
	return recv.totalBytes, recv.chunkCount
}
