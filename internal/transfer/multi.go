// SPDX-License-Identifier: MIT

package transfer

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// globalSeqSize is the number of bytes prepended to data frame payloads
// inside MultiStream for global ordering across streams.
const globalSeqSize = 8

// maxRawFrameSize is the maximum size for a raw (pre-prepared) frame passed
// through MultiStream, including the multiFrame wrapper overhead. This caps
// data + encryption overhead + global seq + wrapper tag at 1 MiB.
const maxRawFrameSize = 1024 * 1024

// MultiStreamConn is the interface that the underlying connections must
// implement for MultiStream to manage deadlines and lifecycle.
type MultiStreamConn interface {
	Close() error
	SetDeadline(t time.Time) error
}

// Compile-time interface checks.
var (
	_ FrameReadWriter       = (*MultiStream)(nil)
	_ ParallelFramePreparer = (*MultiStream)(nil)
	_ DeadlineSetter        = (*MultiStream)(nil)
)

// MultiStream multiplexes data frames across N encrypted streams for
// parallel TCP throughput. Control frames always use stream 0 (primary).
// Data frames get an 8-byte global sequence prefix (inside encryption)
// and are round-robin distributed across streams. The read side
// reassembles data frames in global order.
type MultiStream struct {
	streams []FrameReadWriter // [0]=primary, [1..N-1]=secondary
	conns   []MultiStreamConn // underlying connections for Close/SetDeadline
	n       int

	// Write side
	globalSeq atomic.Uint64           // global data frame counter
	writeMu   sync.Mutex              // protects seqMap
	seqMap    map[uint64]seqMapping   // global seq → (stream, local nonce)

	// Read side
	reassembly *reassembler
	readCancel context.CancelFunc
	readDone   chan struct{} // closed when all reader goroutines exit
	readErr    atomic.Pointer[error]

	// Control frames from stream 0
	controlCh      chan controlFrame
	pendingControl *controlFrame // dequeued but yielded to data; delivered next call

	closeOnce sync.Once
}

type controlFrame struct {
	msgType byte
	data    []byte
}

// NewMultiStream creates a MultiStream from the given encrypted streams
// and their underlying connections. streams[0] is the primary.
func NewMultiStream(streams []FrameReadWriter, conns []MultiStreamConn) *MultiStream {
	if len(streams) != len(conns) {
		panic("MultiStream: streams and conns must have same length")
	}
	n := len(streams)

	ctx, cancel := context.WithCancel(context.Background())
	ms := &MultiStream{
		streams:    streams,
		conns:      conns,
		n:          n,
		seqMap:     make(map[uint64]seqMapping),
		reassembly: newReassembler(),
		readCancel: cancel,
		readDone:   make(chan struct{}),
		controlCh:  make(chan controlFrame, 16),
	}

	// Start N reader goroutines.
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			ms.readLoop(ctx, idx)
		}(i)
	}
	go func() {
		wg.Wait()
		close(ms.readDone)
	}()

	return ms
}

// WriteFrame writes a frame. Control frames go on stream 0; data frames
// are round-robin distributed with a global sequence prefix.
func (ms *MultiStream) WriteFrame(msgType byte, data []byte) error {
	if msgType != MsgData {
		// Control frame: always stream 0.
		return ms.streams[0].WriteFrame(msgType, data)
	}

	// Data frame: prepend global sequence, write to target stream.
	seq := ms.globalSeq.Add(1) - 1
	targetStream := int(seq % uint64(ms.n))

	payload := make([]byte, globalSeqSize+len(data))
	binary.BigEndian.PutUint64(payload[:globalSeqSize], seq)
	copy(payload[globalSeqSize:], data)

	return ms.streams[targetStream].WriteFrame(MsgData, payload)
}

// ReadFrame returns frames in order. Control frames are delivered as-is.
// Data frames are reassembled in global sequence order, with the global
// sequence prefix stripped. Data frames are always prioritized over control
// frames to ensure ordering within the data stream.
func (ms *MultiStream) ReadFrame() (byte, []byte, error) {
	// Always drain buffered data and pending controls before surfacing errors,
	// so callers see MsgDone/MsgComplete even if a secondary stream errored.
	if data, ok := ms.reassembly.tryDeliver(); ok {
		return MsgData, data, nil
	}
	if ms.pendingControl != nil {
		cf := *ms.pendingControl
		ms.pendingControl = nil
		return cf.msgType, cf.data, nil
	}
	if ep := ms.readErr.Load(); ep != nil {
		select {
		case cf := <-ms.controlCh:
			return cf.msgType, cf.data, nil
		default:
		}
		return 0, nil, *ep
	}

	for {
		// Always try to deliver buffered data frames first.
		if data, ok := ms.reassembly.tryDeliver(); ok {
			return MsgData, data, nil
		}

		// If we have a pending control frame and no data is ready, deliver it.
		if ms.pendingControl != nil {
			cf := *ms.pendingControl
			ms.pendingControl = nil
			return cf.msgType, cf.data, nil
		}

		// No data frame ready. Wait for a signal.
		select {
		case <-ms.reassembly.signal():
			// A new data frame arrived — loop to try delivery.
			// Also recheck for errors: a reader may have stored an error
			// and signaled the reassembler concurrently.
			if ep := ms.readErr.Load(); ep != nil {
				// Drain any remaining buffered data before surfacing the error.
				if data, ok := ms.reassembly.tryDeliver(); ok {
					return MsgData, data, nil
				}
				return 0, nil, *ep
			}
			continue
		case cf := <-ms.controlCh:
			// Control frame arrived. Check if any data frames became
			// ready in the meantime — deliver data first.
			if data, ok := ms.reassembly.tryDeliver(); ok {
				ms.pendingControl = &cf
				return MsgData, data, nil
			}
			return cf.msgType, cf.data, nil
		case <-ms.readDone:
			// All readers exited. Drain remaining data frames.
			if data, ok := ms.reassembly.tryDeliver(); ok {
				return MsgData, data, nil
			}
			if ms.pendingControl != nil {
				cf := *ms.pendingControl
				ms.pendingControl = nil
				return cf.msgType, cf.data, nil
			}
			select {
			case cf := <-ms.controlCh:
				return cf.msgType, cf.data, nil
			default:
			}
			if ep := ms.readErr.Load(); ep != nil {
				return 0, nil, *ep
			}
			return 0, nil, fmt.Errorf("all streams closed")
		}
	}
}

// PrepareFrame implements FramePreparer for MultiStream.
// For data frames, it prepends the global sequence and delegates to the
// target stream's PrepareFrame.
func (ms *MultiStream) PrepareFrame(msgType byte, data []byte) ([]byte, error) {
	if msgType != MsgData {
		if fp, ok := ms.streams[0].(FramePreparer); ok {
			return fp.PrepareFrame(msgType, data)
		}
		return nil, fmt.Errorf("stream 0 does not support PrepareFrame")
	}

	seq := ms.globalSeq.Add(1) - 1
	targetStream := int(seq % uint64(ms.n))

	payload := make([]byte, globalSeqSize+len(data))
	binary.BigEndian.PutUint64(payload[:globalSeqSize], seq)
	copy(payload[globalSeqSize:], data)

	if fp, ok := ms.streams[targetStream].(FramePreparer); ok {
		return fp.PrepareFrame(MsgData, payload)
	}
	return nil, fmt.Errorf("stream %d does not support PrepareFrame", targetStream)
}

// WriteRawFrame writes a pre-prepared frame. The frame must have been
// prepared by PrepareFrame or PrepareFrameAt for the correct target stream.
func (ms *MultiStream) WriteRawFrame(frame []byte) error {
	// Reject oversized frames before attempting to parse or route them.
	if len(frame) > maxRawFrameSize {
		return fmt.Errorf("raw frame too large: %d > %d", len(frame), maxRawFrameSize)
	}

	// Since PrepareFrame/PrepareFrameAt encode the target stream in the
	// frame's nonce, we need to route to the correct stream. However,
	// the current pipelining architecture writes frames in order from a
	// single writer goroutine. For MultiStream, we use a different approach:
	// ReserveWriteSeq/PrepareFrameAt return a multiFrame that includes the
	// target stream index, and WriteRawFrame routes accordingly.
	mf, ok := multiFrameFromBytes(frame)
	if !ok {
		// Fallback: control frame, always stream 0.
		if fp, ok := ms.streams[0].(FramePreparer); ok {
			return fp.WriteRawFrame(frame)
		}
		return fmt.Errorf("stream 0 does not support WriteRawFrame")
	}
	if mf.streamIdx < 0 || mf.streamIdx >= ms.n {
		return fmt.Errorf("multiFrame stream index out of range: %d (have %d streams)", mf.streamIdx, ms.n)
	}
	if fp, ok := ms.streams[mf.streamIdx].(FramePreparer); ok {
		return fp.WriteRawFrame(mf.frame)
	}
	return fmt.Errorf("stream %d does not support WriteRawFrame", mf.streamIdx)
}

// multiFrameTag is a magic prefix that identifies a multiFrame wrapper.
// This is never a valid encrypted frame prefix because encrypted frames
// start with a 4-byte big-endian length that won't match these bytes.
var multiFrameTag = [4]byte{0xFF, 0x4D, 0x53, 0x00} // "ÿMS\0"

// multiFrame wraps a prepared frame with routing information.
type multiFrame struct {
	streamIdx int
	frame     []byte
}

// multiFrameToBytes wraps a frame with the stream index for routing.
func multiFrameToBytes(streamIdx int, frame []byte) []byte {
	// Format: [4 tag][1 streamIdx][N frame]
	out := make([]byte, 5+len(frame))
	copy(out[:4], multiFrameTag[:])
	out[4] = byte(streamIdx)
	copy(out[5:], frame)
	return out
}

// multiFrameFromBytes unwraps a multiFrame. Returns false if not a multiFrame.
func multiFrameFromBytes(data []byte) (multiFrame, bool) {
	if len(data) < 5 {
		return multiFrame{}, false
	}
	if data[0] != multiFrameTag[0] || data[1] != multiFrameTag[1] ||
		data[2] != multiFrameTag[2] || data[3] != multiFrameTag[3] {
		return multiFrame{}, false
	}
	return multiFrame{
		streamIdx: int(data[4]),
		frame:     data[5:],
	}, true
}

// ReserveWriteSeq reserves the next global write sequence number and
// returns a combined value encoding both the global seq and target stream.
func (ms *MultiStream) ReserveWriteSeq() (uint64, error) {
	seq := ms.globalSeq.Add(1) - 1
	targetStream := int(seq % uint64(ms.n))

	// Reserve a nonce on the target stream.
	if pp, ok := ms.streams[targetStream].(ParallelFramePreparer); ok {
		localSeq, err := pp.ReserveWriteSeq()
		if err != nil {
			return 0, err
		}
		// Encode: upper 32 bits = target stream + local seq flag, lower 32 = global seq
		// Actually we need to pass all 3 values (globalSeq, targetStream, localSeq)
		// through a single uint64. Use a lookup table instead.
		ms.writeMu.Lock()
		ms.seqMap[seq] = seqMapping{streamIdx: targetStream, localSeq: localSeq}
		ms.writeMu.Unlock()
		return seq, nil
	}
	return 0, fmt.Errorf("stream %d does not support ReserveWriteSeq", targetStream)
}

// seqMapping maps a global sequence number to a stream index and local nonce.
type seqMapping struct {
	streamIdx int
	localSeq  uint64
}

// PrepareFrameAt encrypts a data frame at a pre-reserved sequence number.
func (ms *MultiStream) PrepareFrameAt(msgType byte, data []byte, seq uint64) ([]byte, error) {
	ms.writeMu.Lock()
	mapping, ok := ms.seqMap[seq]
	if ok {
		delete(ms.seqMap, seq)
	}
	ms.writeMu.Unlock()
	if !ok {
		return nil, fmt.Errorf("no mapping for global seq %d", seq)
	}

	// Prepend global sequence to payload.
	payload := make([]byte, globalSeqSize+len(data))
	binary.BigEndian.PutUint64(payload[:globalSeqSize], seq)
	copy(payload[globalSeqSize:], data)

	pp, ok := ms.streams[mapping.streamIdx].(ParallelFramePreparer)
	if !ok {
		return nil, fmt.Errorf("stream %d does not support PrepareFrameAt", mapping.streamIdx)
	}
	frame, err := pp.PrepareFrameAt(MsgData, payload, mapping.localSeq)
	if err != nil {
		return nil, err
	}

	// Wrap with stream routing information.
	return multiFrameToBytes(mapping.streamIdx, frame), nil
}

// StreamCount returns the number of streams in this MultiStream.
func (ms *MultiStream) StreamCount() int {
	return ms.n
}

// SetDeadline sets the deadline on all underlying connections.
func (ms *MultiStream) SetDeadline(t time.Time) error {
	var firstErr error
	for _, c := range ms.conns {
		if err := c.SetDeadline(t); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Close closes all underlying connections and stops reader goroutines.
// Safe to call multiple times (idempotent via sync.Once).
func (ms *MultiStream) Close() error {
	var firstErr error
	ms.closeOnce.Do(func() {
		ms.readCancel()
		for _, c := range ms.conns {
			if err := c.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		ms.reassembly.abort(fmt.Errorf("multi-stream closed"))

		// Clear any stale seqMap entries from reserved-but-unused sequences.
		ms.writeMu.Lock()
		clear(ms.seqMap)
		ms.writeMu.Unlock()
	})
	return firstErr
}

// readLoop reads frames from a single stream and routes them.
func (ms *MultiStream) readLoop(ctx context.Context, streamIdx int) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msgType, data, err := ms.streams[streamIdx].ReadFrame()
		if err != nil {
			// Store error and cancel all readers.
			ms.readErr.CompareAndSwap(nil, &err)
			ms.readCancel()
			ms.reassembly.abort(err)
			return
		}

		if msgType == MsgCancel {
			// Cancel bypasses reassembly — deliver immediately.
			select {
			case ms.controlCh <- controlFrame{msgType: MsgCancel, data: data}:
			default:
			}
			ms.readCancel()
			ms.reassembly.abort(fmt.Errorf("peer cancelled transfer"))
			return
		}

		if msgType != MsgData {
			// Control frame from any stream (should only come from stream 0,
			// but handle gracefully).
			select {
			case ms.controlCh <- controlFrame{msgType: msgType, data: data}:
			case <-ctx.Done():
				return
			}
			continue
		}

		// Data frame: extract global seq prefix, insert into reassembler.
		if len(data) < globalSeqSize {
			err := fmt.Errorf("data frame too small for global seq: %d bytes", len(data))
			ms.readErr.CompareAndSwap(nil, &err)
			ms.readCancel()
			ms.reassembly.abort(err)
			return
		}
		globalSeq := binary.BigEndian.Uint64(data[:globalSeqSize])
		payload := data[globalSeqSize:]
		if err := ms.reassembly.insert(ctx, globalSeq, payload); err != nil {
			ms.readErr.CompareAndSwap(nil, &err)
			ms.readCancel()
			ms.reassembly.abort(err)
			return
		}
	}
}

// reassembler buffers out-of-order data frames and delivers them in
// global sequence order. When the buffer is full (maxAhead frames ahead
// of nextSeq), insert blocks until space is freed by tryDeliver.
type reassembler struct {
	mu       sync.Mutex
	notifyCh chan struct{} // signaled on each insert
	spaceCh  chan struct{} // signaled when tryDeliver frees buffer space
	nextSeq  uint64
	buffer   map[uint64][]byte
	maxAhead int // cap to prevent unbounded memory
	err      error
}

func newReassembler() *reassembler {
	return &reassembler{
		notifyCh: make(chan struct{}, 1),
		spaceCh:  make(chan struct{}, 1),
		buffer:   make(map[uint64][]byte),
		maxAhead: 4096,
	}
}

// signal returns a channel that is signaled when new data arrives.
func (r *reassembler) signal() <-chan struct{} {
	return r.notifyCh
}

// insert adds a frame to the buffer with backpressure. If the buffer is
// full, it blocks until space is freed or the context is cancelled.
// Returns an error only on abort or context cancellation.
func (r *reassembler) insert(ctx context.Context, seq uint64, data []byte) error {
	for {
		r.mu.Lock()
		if r.err != nil {
			r.mu.Unlock()
			return r.err
		}
		if r.maxAhead <= 0 || seq < r.nextSeq+uint64(r.maxAhead) {
			r.buffer[seq] = data
			r.mu.Unlock()
			// Signal that new data is available.
			select {
			case r.notifyCh <- struct{}{}:
			default:
			}
			return nil
		}
		r.mu.Unlock()

		// Buffer full — wait for space or cancellation.
		select {
		case <-r.spaceCh:
			// Space freed — retry.
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// tryDeliver returns the next in-order data frame if available.
func (r *reassembler) tryDeliver() ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	data, ok := r.buffer[r.nextSeq]
	if !ok {
		return nil, false
	}
	delete(r.buffer, r.nextSeq)
	r.nextSeq++
	// Signal that space has been freed for blocked inserters.
	select {
	case r.spaceCh <- struct{}{}:
	default:
	}
	return data, true
}

// abort marks the reassembler as failed and signals any waiting readers.
func (r *reassembler) abort(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err == nil {
		r.err = err
	}
	select {
	case r.notifyCh <- struct{}{}:
	default:
	}
	// Unblock any inserters waiting for space.
	select {
	case r.spaceCh <- struct{}{}:
	default:
	}
}
