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
	heartbeat    *Heartbeat
	totalBytes   uint64
	chunkCount   uint64
	hash         hash.Hash
	decompressor *zstd.Decoder
	OnMetadata   func(*Metadata) // called after metadata is parsed, before data transfer
	// Finalize publishes verified output before Complete is sent. The caller must
	// finish/close its payload sink here; failures are reported to the sender.
	Finalize func() error
	MaxBytes uint64 // zero selects the default 1 TiB receive limit
	// AllowLegacyArchiveSizeMismatch accepts the inaccurate TAR size advertised
	// by legacy v2 CLI senders. It only applies to folder archives; local receive
	// limits and the sender's final byte count and checksum remain enforced.
	AllowLegacyArchiveSizeMismatch bool
}

// NewReceiver creates a new transfer receiver.
func NewReceiver(frw FrameReadWriter) *Receiver {
	if phased, ok := frw.(interface{ ExpectMetadata() }); ok {
		phased.ExpectMetadata()
	}
	return &Receiver{frw: frw, hash: sha256.New()}
}

// SetIdleTimeout configures a per-operation idle timeout.
// The deadline is reset before each read/write operation.
// Session transports own liveness and use this only for physical write timeouts.
func (recv *Receiver) SetIdleTimeout(d DeadlineSetter, timeout time.Duration) {
	if session, ok := recv.frw.(*Session); ok {
		session.SetWriteTimeout(timeout)
		return
	}
	recv.deadliner = d
	recv.idleTimeout = timeout
}

// SetHeartbeat registers a heartbeat that will be touched on every received frame.
func (recv *Receiver) SetHeartbeat(hb *Heartbeat) {
	recv.heartbeat = hb
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

func (recv *Receiver) touchHeartbeat() {
	if recv.heartbeat != nil {
		recv.heartbeat.Touch()
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
	recv.touchHeartbeat()
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
	limit := recv.MaxBytes
	if limit == 0 {
		limit = 1 << 40
	}
	if meta.Size > limit {
		return nil, fmt.Errorf("metadata exceeds receive limit (%d bytes)", limit)
	}
	if recv.OnMetadata != nil {
		recv.OnMetadata(&meta)
	}
	enforceDeclaredSize := !meta.StreamMode && !(recv.AllowLegacyArchiveSizeMismatch && meta.IsFolder)

	// Initialize decompressor if sender indicated compression.
	if meta.Compression == "zstd" {
		dec, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderMaxMemory(MaxChunkSize), zstd.WithDecoderMaxWindow(MaxChunkSize),
			zstd.WithDecodeAllCapLimit(true))
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
		recv.touchHeartbeat()

		switch msgType {
		case MsgHeartbeat:
			continue // silently discard; Touch() already called above

		case MsgCancel:
			return nil, fmt.Errorf("peer cancelled transfer")

		case MsgData:
			// Decompress if compression is enabled.
			if recv.decompressor != nil {
				data, err = recv.decompressor.DecodeAll(data, make([]byte, 0, MaxChunkSize))
				if err != nil {
					WriteError(recv.frw, "decompression failed: "+err.Error())
					return nil, fmt.Errorf("decompressing data: %w", err)
				}
				if len(data) > MaxChunkSize {
					WriteError(recv.frw, "decompressed chunk exceeds maximum size")
					return nil, fmt.Errorf("decompressed chunk too large: %d bytes (max %d)", len(data), MaxChunkSize)
				}
			}
			if len(data) > MaxChunkSize {
				return nil, fmt.Errorf("data chunk exceeds maximum size: %d", len(data))
			}
			if uint64(len(data)) > limit-recv.totalBytes {
				return nil, fmt.Errorf("transfer exceeds receive limit (%d bytes)", limit)
			}
			if enforceDeclaredSize && uint64(len(data)) > meta.Size-recv.totalBytes {
				return nil, fmt.Errorf("transfer exceeds declared size")
			}
			if len(data) == 0 {
				return nil, fmt.Errorf("empty decoded data chunk")
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
			if credits, ok := recv.frw.(interface{ ConsumeData() error }); ok {
				if err := credits.ConsumeData(); err != nil {
					return nil, fmt.Errorf("returning receiver credit: %w", err)
				}
			}
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
			if enforceDeclaredSize && recv.totalBytes != meta.Size {
				return nil, fmt.Errorf("transfer does not match declared size")
			}
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

			if recv.Finalize != nil {
				if err := recv.Finalize(); err != nil {
					WriteError(recv.frw, "output finalization failed")
					return nil, fmt.Errorf("finalizing output: %w", err)
				}
			}

			// Send complete only after verified output has been finalized.
			recv.resetDeadline()
			if err := WriteComplete(recv.frw, &Complete{
				TotalBytes: recv.totalBytes,
				ChunkCount: recv.chunkCount,
				SHA256:     checksum,
			}); err != nil {
				return nil, recv.wrapCtxErr(ctx, fmt.Errorf("sending complete: %w", err))
			}
			// Bound the best-effort acknowledgement wait independently of live
			// heartbeats. Verified, finalized output survives acknowledgement loss.
			ackCtx, ackCancel := context.WithTimeout(ctx, CompletionAckTimeout)
			defer ackCancel()
			if recv.deadliner != nil {
				recv.deadliner.SetDeadline(time.Now().Add(CompletionAckTimeout))
			}
			for {
				var ackType byte
				var ackErr error
				if reader, ok := recv.frw.(interface {
					ReadFrameContext(context.Context) (byte, []byte, error)
				}); ok {
					ackType, _, ackErr = reader.ReadFrameContext(ackCtx)
				} else {
					ackType, _, ackErr = recv.frw.ReadFrame()
				}
				if ackErr != nil || ackType != MsgHeartbeat {
					break
				}
			}
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
		return context.Cause(ctx)
	}
	return err
}

// Stats returns the transfer statistics.
func (recv *Receiver) Stats() (totalBytes, chunkCount uint64) {
	return recv.totalBytes, recv.chunkCount
}
