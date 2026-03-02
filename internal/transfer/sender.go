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

// Sender sends files over a FrameReadWriter (encrypted or plaintext).
type Sender struct {
	frw         FrameReadWriter
	meta        *Metadata
	idleTimeout time.Duration
	deadliner   DeadlineSetter
	totalBytes  uint64
	chunkCount  uint64
	hash        hash.Hash
	compressor  *zstd.Encoder
}

// NewSender creates a new transfer sender.
func NewSender(frw FrameReadWriter, meta *Metadata) *Sender {
	return &Sender{frw: frw, meta: meta, hash: sha256.New()}
}

// SetIdleTimeout configures a per-operation idle timeout.
// The deadline is reset before each read/write operation.
func (s *Sender) SetIdleTimeout(d DeadlineSetter, timeout time.Duration) {
	s.deadliner = d
	s.idleTimeout = timeout
}

func (s *Sender) resetDeadline() {
	if s.deadliner != nil && s.idleTimeout > 0 {
		s.deadliner.SetDeadline(time.Now().Add(s.idleTimeout))
	}
}

func (s *Sender) clearDeadline() {
	if s.deadliner != nil {
		s.deadliner.SetDeadline(time.Time{})
	}
}

// SetCompression enables zstd compression at the given level (1-9).
// Level 0 disables compression. Intermediate values are mapped to the nearest
// zstd speed preset: 1→SpeedFastest, 3→SpeedDefault, 6→SpeedBetterCompression, 9→SpeedBestCompression.
func (s *Sender) SetCompression(level int) error {
	if level <= 0 {
		s.compressor = nil
		return nil
	}
	var speed zstd.EncoderLevel
	switch {
	case level <= 2:
		speed = zstd.SpeedFastest
	case level <= 4:
		speed = zstd.SpeedDefault
	case level <= 7:
		speed = zstd.SpeedBetterCompression
	default:
		speed = zstd.SpeedBestCompression
	}
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(speed))
	if err != nil {
		return fmt.Errorf("creating zstd encoder: %w", err)
	}
	s.compressor = enc
	return nil
}

// Send performs the full send flow: metadata -> data chunks -> done -> wait for complete.
// The context is used for cancellation — when ctx is cancelled, the underlying
// connection deadline is set to the past to unblock any pending I/O.
func (s *Sender) Send(ctx context.Context, r io.Reader, onProgress func(bytesSent uint64)) error {
	defer s.clearDeadline()

	// Watch for context cancellation and force-expire the connection deadline
	// so that any blocked I/O returns immediately.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			if s.deadliner != nil {
				s.deadliner.SetDeadline(time.Now())
			}
		case <-done:
		}
	}()

	// Set compression in metadata if enabled.
	if s.compressor != nil {
		s.meta.Compression = "zstd"
	}

	// Send metadata.
	s.resetDeadline()
	if err := WriteMetadata(s.frw, s.meta); err != nil {
		return s.wrapCtxErr(ctx, fmt.Errorf("sending metadata: %w", err))
	}

	// Send data in chunks.
	buf := make([]byte, MaxChunkSize)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			// Hash and count uncompressed bytes.
			s.hash.Write(chunk)
			s.totalBytes += uint64(n)
			s.chunkCount++
			// Compress if enabled.
			if s.compressor != nil {
				chunk = s.compressor.EncodeAll(chunk, nil)
			}
			s.resetDeadline()
			if writeErr := WriteData(s.frw, chunk); writeErr != nil {
				return s.wrapCtxErr(ctx, fmt.Errorf("sending data chunk: %w", writeErr))
			}
			if onProgress != nil {
				onProgress(s.totalBytes)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return s.wrapCtxErr(ctx, fmt.Errorf("reading input: %w", err))
		}
	}

	// Send done with integrity checksum.
	s.resetDeadline()
	checksum := hex.EncodeToString(s.hash.Sum(nil))
	if err := WriteDone(s.frw, &Done{
		TotalBytes: s.totalBytes,
		ChunkCount: s.chunkCount,
		SHA256:     checksum,
	}); err != nil {
		return s.wrapCtxErr(ctx, fmt.Errorf("sending done: %w", err))
	}

	// Wait for complete.
	s.resetDeadline()
	msgType, data, err := s.frw.ReadFrame()
	if err != nil {
		return s.wrapCtxErr(ctx, fmt.Errorf("waiting for complete: %w", err))
	}

	switch msgType {
	case MsgComplete:
		if len(data) > MaxControlSize {
			return fmt.Errorf("complete message too large: %d bytes (max %d)", len(data), MaxControlSize)
		}
		var complete Complete
		if err := json.Unmarshal(data, &complete); err != nil {
			return fmt.Errorf("parsing complete: %w", err)
		}
		if complete.TotalBytes != s.totalBytes || complete.ChunkCount != s.chunkCount {
			return fmt.Errorf("verification mismatch: sent %d bytes/%d chunks, receiver got %d bytes/%d chunks",
				s.totalBytes, s.chunkCount, complete.TotalBytes, complete.ChunkCount)
		}
		if complete.SHA256 != checksum {
			return fmt.Errorf("integrity mismatch: sender SHA-256 %s, receiver SHA-256 %s", checksum, complete.SHA256)
		}
		// Acknowledge so the receiver knows we received Complete before
		// either side tears down the connection.
		s.resetDeadline()
		WriteFinAck(s.frw) // best-effort
		return nil
	case MsgError:
		if len(data) > MaxControlSize {
			return fmt.Errorf("error message too large: %d bytes", len(data))
		}
		var te TransferError
		if err := json.Unmarshal(data, &te); err != nil {
			return fmt.Errorf("receiver error (malformed): %s", string(data))
		}
		return fmt.Errorf("receiver error: %s", te.Message)
	default:
		return fmt.Errorf("unexpected message type: 0x%02x", msgType)
	}
}

// wrapCtxErr returns ctx.Err() if the context was cancelled, otherwise the original error.
// This provides a clear "context canceled" error instead of a confusing I/O timeout error
// when the user hits Ctrl+C.
func (s *Sender) wrapCtxErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// Stats returns the transfer statistics.
func (s *Sender) Stats() (totalBytes, chunkCount uint64) {
	return s.totalBytes, s.chunkCount
}
