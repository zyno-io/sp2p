// SPDX-License-Identifier: MIT

package transfer

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

const MsgCredit byte = 0x0c

// CreditWindow bounds unconsumed data frames, including compressed frames.
// It is a protocol-v3 constant shared with the browser, not a tunable queue size.
const CreditWindow uint64 = 16

// Profile 1 keeps cumulative frame credits while bounding unconsumed plaintext
// to 64 * 64 KiB = 4 MiB. Only uncompressed senders that explicitly offer it
// receive the new encrypted control; existing v3 peers retain their limits.
const (
	MsgReceiveWindow       byte   = 0x0d
	ReceiveWindowVersion   uint32 = 1
	ReceiveWindowChunks    uint64 = 64
	ReceiveWindowChunkSize        = 64 * 1024
)

const CompletionAckTimeout = 5 * time.Second

const defaultNetworkWriteTimeout = 2 * time.Minute

type sessionFrame struct {
	kind byte
	data []byte
}

// Session owns the read loop and encrypted write ordering for one transfer.
// Frame preparation is deliberately kept inside the write lock: heartbeat and
// credit writes must never overtake a reserved-but-unwritten data nonce.
type Session struct {
	ctx                                context.Context
	cancel                             context.CancelCauseFunc
	frw                                FrameReadWriter
	closer                             io.Closer
	writeMu                            sync.Mutex
	mu                                 sync.Mutex
	sent, credited, received, consumed uint64
	creditChanged                      chan struct{}
	frames                             chan sessionFrame
	lastRecv                           atomic.Int64
	writeTimeout                       atomic.Int64
	closeOnce                          sync.Once
	sender                             bool
	receiveWindow                      uint64
	receiveChunkLimit                  int
	metadataReceived                   bool
}

func NewSession(ctx context.Context, frw FrameReadWriter, closer io.Closer, sender bool) *Session {
	ctx, cancel := context.WithCancelCause(ctx)
	s := &Session{ctx: ctx, cancel: cancel, frw: frw, closer: closer, sender: sender,
		creditChanged: make(chan struct{}, 1), frames: make(chan sessionFrame, ReceiveWindowChunks+16),
		receiveWindow: CreditWindow, receiveChunkLimit: MaxFrameSize}
	if !sender {
		if p, ok := frw.(interface{ ExpectMetadata() }); ok {
			p.ExpectMetadata()
		}
	}
	s.lastRecv.Store(time.Now().UnixNano())
	s.writeTimeout.Store(int64(defaultNetworkWriteTimeout))
	go s.readLoop()
	go s.heartbeatLoop()
	go func() { <-ctx.Done(); s.closeTransport() }()
	return s
}

func (s *Session) Context() context.Context { return s.ctx }
func (s *Session) closeTransport()          { s.closeOnce.Do(func() { s.closer.Close() }) }
func (s *Session) fail(err error)           { s.cancel(err); s.closeTransport() }
func (s *Session) Close() error             { s.fail(context.Canceled); return nil }

// SetWriteTimeout bounds each physical write, not time spent waiting for input,
// receiver credits, or sink finalization. Heartbeats independently bound liveness.
func (s *Session) SetWriteTimeout(timeout time.Duration) {
	if timeout <= 0 {
		timeout = defaultNetworkWriteTimeout
	}
	s.writeTimeout.Store(int64(timeout))
}

func (s *Session) writePhysicalFrame(frw FrameReadWriter, kind byte, data []byte) error {
	timeoutErr := fmt.Errorf("network write timed out")
	writeCtx, cancel := context.WithTimeoutCause(s.ctx, time.Duration(s.writeTimeout.Load()), timeoutErr)
	fired := make(chan struct{})
	stop := context.AfterFunc(writeCtx, func() {
		s.fail(context.Cause(writeCtx))
		close(fired)
	})
	err := frw.WriteFrame(kind, data)
	// Join an already-running callback before another write can start. Merely
	// stopping its timer would allow a stale timeout to close a healthy stream.
	if !stop() {
		<-fired
		// Cancellation may follow a successful write: the peer can consume
		// Complete and close before WriteFrame returns. Preserve that success,
		// but still enforce this write's own timeout even if it returns nil.
		cause := context.Cause(writeCtx)
		if err != nil || cause == timeoutErr {
			err = cause
		}
	}
	cancel()
	return err
}

func (s *Session) WriteFrame(kind byte, data []byte) error {
	if kind == MsgData {
		for {
			s.mu.Lock()
			if s.sent-s.credited < CreditWindow {
				s.sent++
				s.mu.Unlock()
				break
			}
			s.mu.Unlock()
			select {
			case <-s.creditChanged:
			case <-s.ctx.Done():
				return context.Cause(s.ctx)
			}
		}
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := context.Cause(s.ctx); err != nil {
		return err
	}
	var err error
	if multi, ok := s.frw.(*MultiStream); ok {
		err = multi.writeSessionFrame(s.ctx, kind, data, s.writePhysicalFrame)
	} else {
		err = s.writePhysicalFrame(s.frw, kind, data)
	}
	if err != nil {
		s.fail(err)
		return err
	}
	return nil
}

// ConsumeData returns a credit only after the sink has consumed a data frame.
func (s *Session) ConsumeData() error {
	s.mu.Lock()
	if s.consumed >= s.received {
		s.mu.Unlock()
		return fmt.Errorf("invalid data consumption")
	}
	s.consumed++
	consumed := s.consumed
	s.mu.Unlock()
	var data [8]byte
	binary.BigEndian.PutUint64(data[:], consumed)
	return s.WriteFrame(MsgCredit, data[:])
}

func (s *Session) ReadFrame() (byte, []byte, error) {
	return s.ReadFrameContext(s.ctx)
}

// ReadFrameContext bounds an application wait without disrupting the continuous
// transport read owner or leaving a goroutine blocked on a timed-out read.
func (s *Session) ReadFrameContext(ctx context.Context) (byte, []byte, error) {
	// Preserve an already-received Complete even if the peer closes afterward.
	select {
	case f := <-s.frames:
		return f.kind, f.data, nil
	default:
	}
	select {
	case f := <-s.frames:
		return f.kind, f.data, nil
	case <-ctx.Done():
		select {
		case f := <-s.frames:
			return f.kind, f.data, nil
		default:
		}
		return 0, nil, context.Cause(ctx)
	case <-s.ctx.Done():
		select {
		case f := <-s.frames:
			return f.kind, f.data, nil
		default:
		}
		return 0, nil, context.Cause(s.ctx)
	}
}

func (s *Session) readLoop() {
	for {
		kind, data, err := s.frw.ReadFrame()
		if err != nil {
			s.fail(err)
			return
		}
		if kind != MsgData && len(data) > MaxControlSize {
			s.fail(fmt.Errorf("control frame too large"))
			return
		}
		switch kind {
		case MsgHeartbeat:
			if len(data) != 0 {
				s.fail(fmt.Errorf("invalid heartbeat"))
				return
			}
		case MsgCredit:
			if len(data) != 8 {
				s.fail(fmt.Errorf("invalid credit frame"))
				return
			}
			value := binary.BigEndian.Uint64(data)
			s.mu.Lock()
			valid := value > s.credited && value <= s.sent
			if valid {
				s.credited = value
			}
			s.mu.Unlock()
			if !valid {
				s.fail(fmt.Errorf("invalid receiver credit"))
				return
			}
			select {
			case s.creditChanged <- struct{}{}:
			default:
			}
		case MsgData:
			s.mu.Lock()
			valid := !s.sender && len(data) > 0 && len(data) <= s.receiveChunkLimit && s.received-s.consumed < s.receiveWindow
			if valid {
				s.received++
			}
			s.mu.Unlock()
			if !valid {
				s.fail(fmt.Errorf("data exceeds receiver credit or size limit"))
				return
			}
		case MsgError:
			var peerError TransferError
			if err := json.Unmarshal(data, &peerError); err != nil {
				s.fail(fmt.Errorf("malformed peer error: %w", err))
			} else {
				s.fail(fmt.Errorf("peer error: %s", peerError.Message))
			}
			return
		case MsgMetadata:
			if s.metadataReceived || s.sender {
				s.fail(fmt.Errorf("unexpected transfer metadata"))
				return
			}
			s.metadataReceived = true
			var meta Metadata
			if err := json.Unmarshal(data, &meta); err != nil {
				s.fail(fmt.Errorf("invalid metadata: %w", err))
				return
			}
			if meta.ReceiveWindow == ReceiveWindowVersion && meta.Compression == "" {
				s.receiveWindow = ReceiveWindowChunks
				s.receiveChunkLimit = ReceiveWindowChunkSize
				var grant [12]byte
				binary.BigEndian.PutUint32(grant[0:4], ReceiveWindowVersion)
				binary.BigEndian.PutUint32(grant[4:8], uint32(ReceiveWindowChunks))
				binary.BigEndian.PutUint32(grant[8:12], ReceiveWindowChunkSize)
				if err := s.WriteFrame(MsgReceiveWindow, grant[:]); err != nil {
					return
				}
			}
		case MsgDone, MsgComplete, MsgFinAck:
		case MsgCancel:
			s.fail(fmt.Errorf("peer cancelled transfer"))
			return
		default:
			s.fail(fmt.Errorf("unexpected session frame: %x", kind))
			return
		}
		s.lastRecv.Store(time.Now().UnixNano())
		if kind == MsgHeartbeat || kind == MsgCredit {
			continue
		}
		select {
		case s.frames <- sessionFrame{kind, data}:
		case <-s.ctx.Done():
			return
		default:
			s.fail(fmt.Errorf("receive frame queue full"))
			return
		}
	}
}

func (s *Session) heartbeatLoop() {
	ticker := time.NewTicker(HeartbeatInterval)
	defer ticker.Stop()
	// A separate expiry watcher can close I/O even if the serialized heartbeat
	// write is stuck behind a blocked socket write.
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-t.C:
				if time.Since(time.Unix(0, s.lastRecv.Load())) > HeartbeatTimeout {
					s.fail(fmt.Errorf("peer heartbeat timed out"))
					return
				}
			}
		}
	}()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if err := s.WriteFrame(MsgHeartbeat, nil); err != nil {
				return
			}
		}
	}
}
