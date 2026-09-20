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
	"runtime"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/sync/errgroup"
)

// Sender sends files over a FrameReadWriter (encrypted or plaintext).
type Sender struct {
	frw         FrameReadWriter
	meta        *Metadata
	idleTimeout time.Duration
	deadliner   DeadlineSetter
	heartbeat   *Heartbeat
	buffered    BufferedAmounter
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
// For Session transports it instead configures physical write timeouts; Session
// owns peer liveness and permits healthy input/finalization pauses.
// If conn also implements BufferedAmounter, sender progress will be
// adjusted to reflect actual transmission rather than local buffering.
func (s *Sender) SetIdleTimeout(d DeadlineSetter, timeout time.Duration) {
	if session, ok := s.frw.(*Session); ok {
		// Session owns physical write timeouts and peer liveness. An absolute
		// socket deadline here would kill healthy but paused stdin streams.
		session.SetWriteTimeout(timeout)
	} else {
		s.deadliner = d
		s.idleTimeout = timeout
	}
	if ba, ok := d.(BufferedAmounter); ok {
		s.buffered = ba
	}
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

// SetHeartbeat registers a heartbeat that will be touched on every received frame.
func (s *Sender) SetHeartbeat(hb *Heartbeat) {
	s.heartbeat = hb
}

func (s *Sender) touchHeartbeat() {
	if s.heartbeat != nil {
		s.heartbeat.Touch()
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
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(speed), zstd.WithEncoderConcurrency(4), zstd.WithWindowSize(MaxChunkSize))
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

	// Set compression in metadata if enabled.
	if s.compressor != nil {
		s.meta.Compression = "zstd"
		defer s.compressor.Close()
	}

	// The reader hashes in order, bounded workers compress, and the consumer
	// hands ordered chunks to the encrypted transport dispatcher.
	type preparedChunk struct {
		data     []byte // compressed (or raw) chunk ready to encrypt+send
		rawBytes uint64 // uncompressed byte count for progress tracking
		poolBuf  []byte // original read buffer to return to pool (may differ from data if compressed)
	}

	const pipelineDepth = 8
	chunkCh := make(chan preparedChunk, pipelineDepth)
	rawCh := chunkCh
	if s.compressor != nil {
		rawCh = make(chan preparedChunk, pipelineDepth)
	}

	// Pool of read buffers to avoid per-chunk allocations and GC pressure.
	// Safety: when compression is disabled, the buffer is kept alive via
	// preparedChunk.poolBuf and returned to the pool only after the
	// downstream consumer (encrypt worker or writer) has finished with it.
	// When compression is enabled, EncodeAll copies the data, so the buffer
	// is returned immediately.
	bufPool := sync.Pool{New: func() any { return make([]byte, MaxChunkSize) }}

	eg, egCtx := errgroup.WithContext(ctx)

	// closeReader closes r (if it implements io.Closer) exactly once,
	// unblocking a producer stuck in r.Read() on a blocking source
	// (pipe, stdin). Safe for concurrent calls.
	var closeOnce sync.Once
	closeReader := func() {
		closeOnce.Do(func() {
			if rc, ok := r.(io.Closer); ok {
				rc.Close()
			}
		})
	}

	// writeErrMu guards writeErr, which is set by the consumer and
	// read by the producer and the post-Wait error path.
	var writeErrMu sync.Mutex
	var writeErr error
	setWriteErr := func(err error) {
		writeErrMu.Lock()
		writeErr = err
		writeErrMu.Unlock()
	}
	getWriteErr := func() error {
		writeErrMu.Lock()
		defer writeErrMu.Unlock()
		return writeErr
	}

	// Watch for context cancellation and force-expire the connection
	// deadline so that any blocked I/O returns immediately. Also close
	// the reader to unblock a producer stuck in r.Read(). This must
	// start before WriteMetadata so that a stalled metadata write is
	// also unblocked by ctx cancellation.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			if s.deadliner != nil {
				s.deadliner.SetDeadline(time.Now())
			}
			closeReader()
		case <-done:
		}
	}()

	// Send metadata.
	s.resetDeadline()
	if err := WriteMetadata(s.frw, s.meta); err != nil {
		return s.wrapCtxErr(ctx, fmt.Errorf("sending metadata: %w", err))
	}

	// Stage 1 — Reader owns hashing and global chunk order.
	eg.Go(func() error {
		defer close(rawCh)
		for {
			buf := bufPool.Get().([]byte)
			var n int
			var err error
			if s.meta.StreamMode {
				n, err = r.Read(buf) // preserve interactive pipe latency
			} else {
				n, err = io.ReadFull(r, buf) // coalesce TAR headers/padding and short file reads
				if err == io.ErrUnexpectedEOF {
					err = io.EOF
				}
			}
			if n > 0 {
				chunk := buf[:n]
				s.hash.Write(chunk)
				s.totalBytes += uint64(n)
				s.chunkCount++
				prepared := preparedChunk{data: chunk, rawBytes: uint64(n), poolBuf: buf}
				select {
				case rawCh <- prepared:
				case <-egCtx.Done():
					return egCtx.Err()
				}
			} else {
				bufPool.Put(buf)
			}
			if err == io.EOF {
				return nil
			}
			if err != nil {
				// If a downstream stage already failed with a write error,
				// return it instead of the read-side error (which was
				// caused by closing r to unblock this goroutine).
				if wErr := getWriteErr(); wErr != nil {
					return wErr
				}
				return fmt.Errorf("reading input: %w", err)
			}
		}
	})

	// Bounded parallel compression, with ordered futures so compression speed
	// cannot change file order or reserve encrypted nonces out of order.
	if s.compressor != nil {
		type compressionJob struct {
			chunk  preparedChunk
			result chan preparedChunk
		}
		jobs := make(chan compressionJob, 4)
		futures := make(chan chan preparedChunk, pipelineDepth)
		eg.Go(func() error {
			defer close(jobs)
			defer close(futures)
			for chunk := range rawCh {
				result := make(chan preparedChunk, 1)
				select {
				case futures <- result:
				case <-egCtx.Done():
					return egCtx.Err()
				}
				select {
				case jobs <- compressionJob{chunk, result}:
				case <-egCtx.Done():
					return egCtx.Err()
				}
			}
			return nil
		})
		for i := 0; i < min(4, runtime.GOMAXPROCS(0)); i++ {
			eg.Go(func() error {
				for job := range jobs {
					if egCtx.Err() != nil {
						return egCtx.Err()
					}
					data := s.compressor.EncodeAll(job.chunk.data, nil)
					bufPool.Put(job.chunk.poolBuf)
					job.result <- preparedChunk{data: data, rawBytes: job.chunk.rawBytes}
				}
				return nil
			})
		}
		eg.Go(func() error {
			defer close(chunkCh)
			for future := range futures {
				var chunk preparedChunk
				select {
				case chunk = <-future:
				case <-egCtx.Done():
					return egCtx.Err()
				}
				select {
				case chunkCh <- chunk:
				case <-egCtx.Done():
					return egCtx.Err()
				}
			}
			return nil
		})
	}

	// adjustProgress converts total raw bytes and wire bytes into an
	// adjusted progress value that subtracts data still buffered locally
	// (e.g. in the WebRTC DataChannel). This makes the sender's reported
	// progress match what the receiver has actually received.
	adjustProgress := func(rawTotal, wireTotal uint64) uint64 {
		if s.buffered == nil || wireTotal == 0 {
			return rawTotal
		}
		buffered := s.buffered.BufferedAmount()
		if buffered >= wireTotal {
			return 0
		}
		// Convert buffered wire bytes to equivalent raw bytes using
		// the cumulative raw/wire ratio (accounts for compression).
		bufferedRaw := buffered * rawTotal / wireTotal
		if bufferedRaw >= rawTotal {
			return 0
		}
		return rawTotal - bufferedRaw
	}

	// When the FrameReadWriter supports parallel frame preparation,
	// fan out compression + encryption to N worker goroutines. Frames
	// are reassembled in order using per-chunk "future" channels.
	//
	// Pipeline:
	//   Reader (1):   read → hash → compress → reserve nonce → dispatch
	//   Workers (N):  encrypt (parallel, out of order)
	//   Writer (1):   consume futures in order → write to network
	//
	// Falls back to a single-threaded encrypt stage (FramePreparer)
	// or a 2-stage pipeline (plain FrameReadWriter).
	var progressBytes uint64
	var wireBytes uint64

	type wireFrame struct {
		data     []byte // encrypted, wire-ready frame
		rawBytes uint64 // uncompressed byte count for progress
	}

	if pp, ok := s.frw.(ParallelFramePreparer); ok {
		type workItem struct {
			chunk    preparedChunk
			seq      uint64
			resultCh chan<- wireFrame
		}

		numWorkers := min(4, runtime.GOMAXPROCS(0))
		if numWorkers < 2 {
			numWorkers = 2
		}
		workCh := make(chan workItem, numWorkers)
		futureCh := make(chan (<-chan wireFrame), pipelineDepth)

		// Dispatcher: reserve nonces in order, fan out to workers,
		// send result futures to writer in order.
		eg.Go(func() error {
			defer close(futureCh)
			defer close(workCh)
			for chunk := range chunkCh {
				seq, err := pp.ReserveWriteSeq()
				if err != nil {
					return err
				}
				ch := make(chan wireFrame, 1)
				// Send future to writer first (maintains order).
				select {
				case futureCh <- ch:
				case <-egCtx.Done():
					return egCtx.Err()
				}
				// Send work to a worker.
				select {
				case workCh <- workItem{chunk: chunk, seq: seq, resultCh: ch}:
				case <-egCtx.Done():
					return egCtx.Err()
				}
			}
			return nil
		})

		// Workers: encrypt in parallel. Compression (if any) was already
		// done by the reader stage, so data is ready to encrypt.
		for i := 0; i < numWorkers; i++ {
			eg.Go(func() error {
				for work := range workCh {
					frame, err := pp.PrepareFrameAt(MsgData, work.chunk.data, work.seq)
					// Return read buffer after encryption has copied the data.
					if work.chunk.poolBuf != nil {
						bufPool.Put(work.chunk.poolBuf)
					}
					if err != nil {
						setWriteErr(fmt.Errorf("encrypting data chunk: %w", err))
						closeReader()
						return getWriteErr()
					}
					work.resultCh <- wireFrame{data: frame, rawBytes: work.chunk.rawBytes}
				}
				return nil
			})
		}

		// Writer: consume futures in nonce order → write to network.
		eg.Go(func() error {
			for future := range futureCh {
				var frame wireFrame
				select {
				case frame = <-future:
				case <-egCtx.Done():
					return egCtx.Err()
				}
				s.resetDeadline()
				if err := pp.WriteRawFrame(frame.data); err != nil {
					setWriteErr(fmt.Errorf("sending data chunk: %w", err))
					closeReader()
					return getWriteErr()
				}
				progressBytes += frame.rawBytes
				wireBytes += uint64(len(frame.data))
				if onProgress != nil {
					onProgress(adjustProgress(progressBytes, wireBytes))
				}
			}
			return nil
		})
	} else if preparer, ok := s.frw.(FramePreparer); ok {
		// 3-stage fallback: single encrypt goroutine.
		frameCh := make(chan wireFrame, pipelineDepth)

		eg.Go(func() error {
			defer close(frameCh)
			for chunk := range chunkCh {
				frame, err := preparer.PrepareFrame(MsgData, chunk.data)
				if chunk.poolBuf != nil {
					bufPool.Put(chunk.poolBuf)
				}
				if err != nil {
					setWriteErr(fmt.Errorf("encrypting data chunk: %w", err))
					closeReader()
					return getWriteErr()
				}
				select {
				case frameCh <- wireFrame{data: frame, rawBytes: chunk.rawBytes}:
				case <-egCtx.Done():
					return egCtx.Err()
				}
			}
			return nil
		})

		eg.Go(func() error {
			for frame := range frameCh {
				s.resetDeadline()
				if err := preparer.WriteRawFrame(frame.data); err != nil {
					setWriteErr(fmt.Errorf("sending data chunk: %w", err))
					closeReader()
					return getWriteErr()
				}
				progressBytes += frame.rawBytes
				wireBytes += uint64(len(frame.data))
				if onProgress != nil {
					onProgress(adjustProgress(progressBytes, wireBytes))
				}
			}
			return nil
		})
	} else {
		// 2-stage fallback: consumer does encrypt + write via WriteFrame.
		eg.Go(func() error {
			for chunk := range chunkCh {
				s.resetDeadline()
				if err := WriteData(s.frw, chunk.data); err != nil {
					setWriteErr(fmt.Errorf("sending data chunk: %w", err))
					closeReader()
					return getWriteErr()
				}
				if chunk.poolBuf != nil {
					bufPool.Put(chunk.poolBuf)
				}
				progressBytes += chunk.rawBytes
				wireBytes += uint64(len(chunk.data))
				if onProgress != nil {
					onProgress(adjustProgress(progressBytes, wireBytes))
				}
			}
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		// Prefer the write error over a read-side error from closing r.
		if wErr := getWriteErr(); wErr != nil {
			return s.wrapCtxErr(ctx, wErr)
		}
		return s.wrapCtxErr(ctx, err)
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

	// Wait for complete, skipping incoming heartbeats.
	// The receiver sends Complete promptly after verification, so this
	// wait is brief. The idle timeout covers pathological delays.
	var msgType byte
	var data []byte
	var err error
	for {
		s.resetDeadline()
		msgType, data, err = s.frw.ReadFrame()
		if err != nil {
			return s.wrapCtxErr(ctx, fmt.Errorf("waiting for complete: %w", err))
		}
		s.touchHeartbeat()
		if msgType == MsgHeartbeat {
			continue
		}
		if msgType == MsgCancel {
			return fmt.Errorf("peer cancelled transfer")
		}
		break
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
		return context.Cause(ctx)
	}
	return err
}

// Stats returns the transfer statistics.
func (s *Sender) Stats() (totalBytes, chunkCount uint64) {
	return s.totalBytes, s.chunkCount
}
