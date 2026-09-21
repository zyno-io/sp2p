// SPDX-License-Identifier: MIT

// Package stream provides the stream/1 application protocol over an already
// authenticated encrypted peer transport.  It is deliberately single-stream:
// multiplexing belongs to a future protocol version rather than adding hidden
// connection IDs to this wire format.
package stream

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zyno-io/sp2p/internal/crypto"
)

const (
	protocolName = "stream/1"
	maxDataSize  = 64 * 1024
	maxFrames    = 16

	msgHello        byte = 0x40
	msgHandshakeAck byte = 0x41
	msgData         byte = 0x42
	msgCredit       byte = 0x43
	msgFin          byte = 0x44
	msgFinAck       byte = 0x45
	msgStatus       byte = 0x46
	msgAbort        byte = 0x47
	msgHeartbeat    byte = 0x48
	msgReady        byte = 0x49
	msgStatusAck    byte = 0x4A

	handshakeTimeout = 10 * time.Second
	heartbeatEvery   = 15 * time.Second
	peerIdleTimeout  = 45 * time.Second
	finishTimeout    = 30 * time.Second
	abortTimeout     = 2 * time.Second
)

// physicalWriteTimeout bounds one blocked transport write. It is independent
// of inbound heartbeats: a peer that keeps sending but stops reading must not
// retain an unbounded local writer forever.
var physicalWriteTimeout = 30 * time.Second

// Config describes the authenticated application selected by stream/1.  Each
// peer sends Service and Mode. ExpectedService and ExpectedMode constrain the
// peer's corresponding declaration; an empty expected value accepts any value.
type Config struct {
	Service         string
	Mode            string
	ExpectedService string
	ExpectedMode    string
}

type hello struct {
	Protocol       string `json:"protocol"`
	Service        string `json:"service"`
	Mode           string `json:"mode"`
	MaxData        int    `json:"maxData"`
	MaxOutstanding int    `json:"maxOutstanding"`
}

type status struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type writeRequest struct {
	typ  byte
	data []byte
	done chan error
}

// Stream is a bounded, full-duplex byte stream.  One goroutine owns encrypted
// reads and every physical write is serialized before encryption, preserving
// cipher-counter and wire ordering even when controls race application writes.
type Stream struct {
	ctx          context.Context
	cancel       context.CancelFunc
	frames       *crypto.EncryptedStream
	closer       io.Closer
	writeTimeout time.Duration

	dataWriteMu sync.Mutex
	writeCh     chan writeRequest

	handshakeMu sync.Mutex
	handshaken  bool
	helloCh     chan hello
	ackCh       chan hello

	dataCh          chan []byte
	dataCloseOnce   sync.Once
	remoteDrainOnce sync.Once
	readMu          sync.Mutex
	readBuf         []byte

	creditMu     sync.Mutex
	peerCredit   uint64 // cumulative consumed frames reported by the peer
	framesSent   uint64
	framesRead   uint64
	creditNotify chan struct{}

	stateMu                   sync.Mutex
	localFin                  bool
	remoteFin                 bool
	localFinAck               bool
	localReady                bool
	remoteReady               bool
	localStatus               bool
	localStatusAck            bool
	remoteStatus              *status
	terminalErr               error
	localAckCh                chan struct{}
	remoteFinCh               chan struct{}
	remoteDrainCh             chan struct{}
	remoteReadyCh             chan struct{}
	remoteStatCh              chan struct{}
	localStatAckCh            chan struct{}
	localStatusWriteDoneCh    chan struct{}
	localStatusWriteQueued    bool
	localStatusWriteCompleted bool
	localStatusWriteErr       error
	remoteStatAckWrittenCh    chan struct{}
	remoteStatAckWriteDoneCh  chan struct{}
	remoteStatAckQueued       bool
	remoteStatAckCompleted    bool
	remoteStatAckWriteErr     error
	writerStopped             bool
	abortOnce                 sync.Once
	abortResult               error

	sent     atomic.Uint64
	received atomic.Uint64
	lastRead atomic.Int64
}

// New creates a stream and starts its sole frame reader.  closer is normally
// the conn.P2PConn from peer.Result; closing it is how cancellation unblocks
// TCP and WebRTC reads/writes.
func New(ctx context.Context, frames *crypto.EncryptedStream, closer io.Closer) *Stream {
	childCtx, cancel := context.WithCancel(ctx)
	s := &Stream{
		ctx: childCtx, cancel: cancel, frames: frames, closer: closer, writeTimeout: physicalWriteTimeout,
		helloCh: make(chan hello, 1), ackCh: make(chan hello, 1),
		dataCh: make(chan []byte, maxFrames), creditNotify: make(chan struct{}, 1),
		localAckCh: make(chan struct{}), remoteFinCh: make(chan struct{}),
		remoteDrainCh: make(chan struct{}), remoteReadyCh: make(chan struct{}),
		remoteStatCh: make(chan struct{}), localStatAckCh: make(chan struct{}), localStatusWriteDoneCh: make(chan struct{}),
		remoteStatAckWrittenCh:   make(chan struct{}),
		remoteStatAckWriteDoneCh: make(chan struct{}), writeCh: make(chan writeRequest, maxFrames+16),
	}
	s.lastRead.Store(time.Now().UnixNano())
	go s.writeFrames()
	go s.readFrames()
	go s.heartbeats()
	context.AfterFunc(childCtx, func() { s.closeTransport() })
	return s
}

// Handshake establishes stream/1 and authenticates the requested application
// inside the encrypted channel.  It is bounded independently of peer setup.
func (s *Stream) Handshake(ctx context.Context, cfg Config) error {
	if cfg.Service == "" || cfg.Mode == "" {
		return fmt.Errorf("stream service and mode are required")
	}
	s.handshakeMu.Lock()
	defer s.handshakeMu.Unlock()
	if s.handshaken {
		return fmt.Errorf("stream handshake already completed")
	}
	deadlineCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	stopDeadline := s.cancelTransportAtDeadline(deadlineCtx)
	defer stopDeadline()

	mine := hello{Protocol: protocolName, Service: cfg.Service, Mode: cfg.Mode, MaxData: maxDataSize, MaxOutstanding: maxFrames}
	if err := s.send(deadlineCtx, msgHello, mustJSON(mine)); err != nil {
		return fmt.Errorf("sending stream handshake: %w", err)
	}
	var peer hello
	select {
	case peer = <-s.helloCh:
	case <-deadlineCtx.Done():
		return deadlineCtx.Err()
	case <-s.ctx.Done():
		return s.terminalError()
	}
	if err := validateHello(peer, cfg); err != nil {
		s.fail(err)
		return err
	}
	if err := s.send(deadlineCtx, msgHandshakeAck, mustJSON(mine)); err != nil {
		return fmt.Errorf("acknowledging stream handshake: %w", err)
	}
	var peerAck hello
	select {
	case peerAck = <-s.ackCh:
	case <-deadlineCtx.Done():
		return deadlineCtx.Err()
	case <-s.ctx.Done():
		return s.terminalError()
	}
	if err := validateHello(peerAck, cfg); err != nil {
		return fmt.Errorf("peer rejected stream handshake: %w", err)
	}
	// Credits are cumulative consumed-frame counts. The peer's advertised
	// outstanding limit is validated above; no frame has been consumed yet.
	s.creditMu.Lock()
	s.peerCredit = 0
	s.creditMu.Unlock()
	s.handshaken = true
	return nil
}

// Ready declares that the local endpoint is ready to exchange application
// bytes. It is distinct from Handshake so a provider never dials its fixed
// target before the connector has accepted its local endpoint.
func (s *Stream) Ready() error {
	if !s.isHandshaken() {
		return fmt.Errorf("stream handshake is not complete")
	}
	s.stateMu.Lock()
	if s.localReady {
		s.stateMu.Unlock()
		return fmt.Errorf("stream ready already sent")
	}
	s.localReady = true
	s.stateMu.Unlock()
	if err := s.send(s.ctx, msgReady, nil); err != nil {
		s.fail(err)
		return err
	}
	return nil
}

// WaitReady waits for the peer's endpoint-ready control. A peer failure is
// returned directly rather than being mistaken for a ready endpoint.
func (s *Stream) WaitReady(ctx context.Context) error {
	for {
		s.stateMu.Lock()
		remoteStatus := s.remoteStatus
		ready := s.remoteReady
		s.stateMu.Unlock()
		if remoteStatus != nil {
			if remoteStatus.OK {
				return fmt.Errorf("peer completed stream before endpoint ready")
			}
			return errors.New(remoteStatus.Error)
		}
		if ready {
			return nil
		}
		select {
		case <-s.remoteReadyCh:
		case <-s.remoteStatCh:
		case <-s.ctx.Done():
			// Loop once to prefer a status which raced the transport failure.
			s.stateMu.Lock()
			status := s.remoteStatus
			s.stateMu.Unlock()
			if status != nil {
				continue
			}
			return s.terminalError()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Read receives application bytes.  EOF is directional: it is returned only
// after every data frame preceding the peer FIN has been delivered.
func (s *Stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()
	for len(s.readBuf) == 0 {
		select {
		case chunk, ok := <-s.dataCh:
			if !ok {
				s.stateMu.Lock()
				remoteFIN := s.remoteFin
				s.stateMu.Unlock()
				if !remoteFIN {
					return 0, s.terminalError()
				}
				s.remoteDrainOnce.Do(func() { close(s.remoteDrainCh) })
				return 0, io.EOF
			}
			s.readBuf = chunk
		case <-s.ctx.Done():
			return 0, s.terminalError()
		}
	}
	n := copy(p, s.readBuf)
	s.readBuf = s.readBuf[n:]
	if len(s.readBuf) == 0 {
		s.framesRead++
		s.sendCredit()
	}
	return n, nil
}

// Write sends p as at most 64KiB data frames. Writes wait for the peer's
// cumulative credit without holding the physical writer lock.
func (s *Stream) Write(p []byte) (int, error) {
	if !s.isHandshaken() {
		return 0, fmt.Errorf("stream handshake is not complete")
	}
	s.stateMu.Lock()
	closed := s.localFin
	ready := s.localReady && s.remoteReady
	s.stateMu.Unlock()
	if !ready {
		return 0, fmt.Errorf("stream endpoints are not ready")
	}
	if closed {
		return 0, io.ErrClosedPipe
	}
	s.dataWriteMu.Lock()
	defer s.dataWriteMu.Unlock()
	s.stateMu.Lock()
	closed = s.localFin
	ready = s.localReady && s.remoteReady
	s.stateMu.Unlock()
	if !ready {
		return 0, fmt.Errorf("stream endpoints are not ready")
	}
	if closed {
		return 0, io.ErrClosedPipe
	}
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxDataSize {
			n = maxDataSize
		}
		if err := s.waitCredit(); err != nil {
			return written, err
		}
		// Reserve the cumulative sequence before writing. A very fast peer
		// can return its credit as soon as this frame reaches the wire.
		s.creditMu.Lock()
		s.framesSent++
		s.creditMu.Unlock()
		chunk := p[:n]
		if err := s.send(s.ctx, msgData, chunk); err != nil {
			s.fail(err)
			return written, err
		}
		s.sent.Add(uint64(n))
		written += n
		p = p[n:]
	}
	return written, nil
}

// CloseWrite sends a directional FIN. The opposite direction remains usable.
func (s *Stream) CloseWrite() error {
	if !s.isHandshaken() {
		return fmt.Errorf("stream handshake is not complete")
	}
	s.dataWriteMu.Lock()
	defer s.dataWriteMu.Unlock()
	s.stateMu.Lock()
	if !s.localReady || !s.remoteReady {
		s.stateMu.Unlock()
		return fmt.Errorf("stream endpoints are not ready")
	}
	if s.localFin {
		s.stateMu.Unlock()
		return nil
	}
	s.localFin = true
	s.stateMu.Unlock()
	if err := s.send(s.ctx, msgFin, nil); err != nil {
		s.fail(err)
		return err
	}
	return nil
}

// Finish records the local endpoint outcome.  A successful finish requires a
// complete half-close in both directions and exchanges terminal status with the
// peer, so transport loss can never be reported as a successful EOF.
func (s *Stream) Finish(err error) error {
	finishCtx, cancel := context.WithTimeout(s.ctx, finishTimeout)
	defer cancel()
	stopDeadline := s.cancelTransportAtDeadline(finishCtx)
	defer stopDeadline()
	if err == nil {
		if finishErr := s.waitGraceful(finishCtx); finishErr != nil {
			return finishErr
		}
	}
	s.stateMu.Lock()
	if s.localStatus {
		s.stateMu.Unlock()
		return fmt.Errorf("stream status already sent")
	}
	s.localStatus = true
	s.stateMu.Unlock()
	local := status{OK: err == nil}
	if err != nil {
		local.Error = limitedError(err)
	}
	if sendErr := s.sendStatus(finishCtx, mustJSON(local)); sendErr != nil {
		s.fail(sendErr)
		if err != nil {
			return err
		}
		return sendErr
	}
	if err != nil {
		// A WebRTC write only queues bytes in Pion. Keep the peer connection
		// alive until SCTP acknowledges the failure status (or this bounded
		// finish context expires), so cleanup cannot replace the authenticated
		// reason with a generic transport EOF. The local endpoint error remains
		// the result even if the best-effort drain itself fails.
		if drainer, ok := s.closer.(interface{ Drain(context.Context) error }); ok {
			_ = drainer.Drain(finishCtx)
		}
		return err
	}
	if err := s.Wait(finishCtx); err != nil {
		return err
	}
	if err := s.waitTerminalControl(finishCtx, s.localStatAckCh); err != nil {
		return err
	}
	if err := s.waitStatusAckWrite(finishCtx); err != nil {
		return err
	}
	if drainer, ok := s.closer.(interface{ Drain(context.Context) error }); ok {
		if err := drainer.Drain(finishCtx); err != nil {
			// BufferedAmount is released by SCTP SACK. The peer may validly
			// close immediately after reading our final ACK, racing the local
			// SACK callback. Once both authenticated status directions and our
			// ACK write are proven, that late transport close is graceful.
			if s.successTerminalProof() && s.lateTransportClosure(finishCtx) {
				return nil
			}
			return fmt.Errorf("draining terminal stream controls: %w", err)
		}
	}
	return nil
}

func (s *Stream) waitTerminalControl(ctx context.Context, done <-chan struct{}) error {
	select {
	case <-done:
		return nil
	default:
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		select {
		case <-done:
			return nil
		default:
			return s.terminalError()
		}
	}
}

func (s *Stream) waitStatusAckWrite(ctx context.Context) error {
	select {
	case <-s.remoteStatAckWrittenCh:
		return nil
	default:
	}
	select {
	case <-s.remoteStatAckWrittenCh:
		return nil
	case <-s.remoteStatAckWriteDoneCh:
		return s.statusAckWriteResult()
	case <-ctx.Done():
		s.stateMu.Lock()
		queued := s.remoteStatAckQueued
		done := s.remoteStatAckCompleted
		s.stateMu.Unlock()
		if queued {
			// The transport can report peer EOF after delivering this ACK but
			// before WriteFrame returns. Join that bounded physical write so its
			// successful completion cannot be lost to context cancellation.
			if !done {
				<-s.remoteStatAckWriteDoneCh
			}
			return s.statusAckWriteResult()
		}
		return s.terminalError()
	}
}

func (s *Stream) statusAckWriteResult() error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.remoteStatAckWriteErr != nil {
		return s.remoteStatAckWriteErr
	}
	return nil
}

func (s *Stream) waitStatusWrite(ctx context.Context) error {
	select {
	case <-s.localStatusWriteDoneCh:
		return s.statusWriteResult()
	case <-s.ctx.Done():
	case <-ctx.Done():
	}

	// Queueing is synchronized with writer shutdown, and every physical write
	// is bounded. If EOF raced a delivered status, join the writer before
	// deciding whether the status send succeeded.
	s.stateMu.Lock()
	done := s.localStatusWriteCompleted
	s.stateMu.Unlock()
	if !done {
		<-s.localStatusWriteDoneCh
	}
	return s.statusWriteResult()
}

func (s *Stream) statusWriteResult() error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.localStatusWriteErr
}

func (s *Stream) successTerminalProof() bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.localStatus && s.localStatusAck && s.remoteStatus != nil && s.remoteStatus.OK
}

func (s *Stream) lateTransportClosure(finishCtx context.Context) bool {
	if errors.Is(finishCtx.Err(), context.DeadlineExceeded) {
		return false
	}
	err := s.terminalError()
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed)
}

// Wait waits for authenticated terminal status from the peer.
func (s *Stream) Wait(ctx context.Context) error {
	select {
	case <-s.remoteStatCh:
		return s.remoteCompletionError()
	default:
	}
	select {
	case <-s.remoteStatCh:
		return s.remoteCompletionError()
	case <-s.ctx.Done():
		// The peer may have sent an authenticated terminal status immediately
		// before closing its transport. Prefer that proof to a later EOF.
		select {
		case <-s.remoteStatCh:
			return s.remoteCompletionError()
		default:
			return s.terminalError()
		}
	case <-ctx.Done():
		// Prefer an authenticated status that became ready alongside the
		// caller's cancellation, just as we do for stream cancellation above.
		select {
		case <-s.remoteStatCh:
			return s.remoteCompletionError()
		default:
			return ctx.Err()
		}
	}
}

// Close aborts the physical stream. It is idempotent and unblocks all local
// readers/writers. Call Finish for an authenticated graceful result instead.
func (s *Stream) Close() error {
	s.fail(io.ErrClosedPipe)
	return nil
}

// Abort makes a bounded best-effort authenticated abort visible to the peer,
// then closes the physical transport. It is intended for adapter failures that
// occur before Finish can complete its graceful EOF/status exchange.
func (s *Stream) Abort(err error) error {
	s.abortOnce.Do(func() {
		if err == nil {
			err = errors.New("stream aborted")
		}
		abortCtx, cancel := context.WithTimeout(context.Background(), abortTimeout)
		defer cancel()
		stopDeadline := s.cancelTransportAtDeadline(abortCtx)
		defer stopDeadline()
		sendErr := s.send(abortCtx, msgAbort, []byte(limitedError(err)))
		s.fail(err)
		if sendErr != nil {
			s.abortResult = sendErr
			return
		}
		s.abortResult = err
	})
	return s.abortResult
}

// Stats returns application payload bytes sent and received.
func (s *Stream) Stats() (sent, received uint64) { return s.sent.Load(), s.received.Load() }

// Context is canceled when the peer aborts, the transport is lost, or Close
// is called. Adapters use it to stop a pending local accept or child startup.
func (s *Stream) Context() context.Context { return s.ctx }

func (s *Stream) readFrames() {
	helloSeen := false
	ackSeen := false
	for {
		typ, data, err := s.frames.ReadFrame()
		if err != nil {
			s.fail(fmt.Errorf("reading stream frame: %w", err))
			return
		}
		s.lastRead.Store(time.Now().UnixNano())
		if typ != msgData && len(data) > 4*1024 {
			s.fail(fmt.Errorf("stream control frame too large"))
			return
		}
		s.stateMu.Lock()
		terminal := s.remoteStatus != nil
		s.stateMu.Unlock()
		if terminal && typ != msgHeartbeat && typ != msgStatusAck {
			s.fail(fmt.Errorf("stream frame after terminal status"))
			return
		}
		switch typ {
		case msgHello:
			if helloSeen {
				s.fail(fmt.Errorf("duplicate stream hello"))
				return
			}
			helloSeen = true
			var value hello
			if err := json.Unmarshal(data, &value); err != nil {
				s.fail(fmt.Errorf("invalid stream hello: %w", err))
				return
			}
			select {
			case s.helloCh <- value:
			default:
				s.fail(fmt.Errorf("duplicate stream hello"))
				return
			}
		case msgHandshakeAck:
			if ackSeen {
				s.fail(fmt.Errorf("duplicate stream acknowledgement"))
				return
			}
			ackSeen = true
			var value hello
			if err := json.Unmarshal(data, &value); err != nil {
				s.fail(fmt.Errorf("invalid stream acknowledgement: %w", err))
				return
			}
			select {
			case s.ackCh <- value:
			default:
				s.fail(fmt.Errorf("duplicate stream acknowledgement"))
				return
			}
		case msgData:
			if !s.isHandshaken() || len(data) == 0 || len(data) > maxDataSize {
				s.fail(fmt.Errorf("invalid stream data frame"))
				return
			}
			s.stateMu.Lock()
			finished := s.remoteFin
			ready := s.localReady && s.remoteReady
			s.stateMu.Unlock()
			if !ready || finished {
				s.fail(fmt.Errorf("data after peer FIN"))
				return
			}
			// A conforming peer has only maxFrames credits. Never let an
			// over-credit peer block the sole control reader or grow memory.
			select {
			case s.dataCh <- data:
			default:
				s.fail(fmt.Errorf("peer exceeded stream receive credit"))
				return
			}
			s.received.Add(uint64(len(data)))
		case msgCredit:
			if len(data) != 8 {
				s.fail(fmt.Errorf("invalid stream credit"))
				return
			}
			credit := binary.BigEndian.Uint64(data)
			s.creditMu.Lock()
			if credit < s.peerCredit || credit > s.framesSent {
				s.creditMu.Unlock()
				s.fail(fmt.Errorf("invalid cumulative stream credit"))
				return
			}
			s.peerCredit = credit
			s.creditMu.Unlock()
			s.notifyCredit()
		case msgFin:
			s.stateMu.Lock()
			if !s.localReady || !s.remoteReady {
				s.stateMu.Unlock()
				s.fail(fmt.Errorf("stream FIN before endpoints ready"))
				return
			}
			if s.remoteFin {
				s.stateMu.Unlock()
				s.fail(fmt.Errorf("duplicate stream FIN"))
				return
			}
			s.remoteFin = true
			s.stateMu.Unlock()
			close(s.remoteFinCh)
			s.closeData()
			if !s.queueControl(msgFinAck, nil) {
				return
			}
		case msgFinAck:
			s.stateMu.Lock()
			if !s.localFin || s.localFinAck {
				s.stateMu.Unlock()
				s.fail(fmt.Errorf("unexpected stream FIN acknowledgement"))
				return
			}
			s.localFinAck = true
			s.stateMu.Unlock()
			close(s.localAckCh)
		case msgStatus:
			var value status
			if err := json.Unmarshal(data, &value); err != nil || (value.OK && value.Error != "") || (!value.OK && value.Error == "") {
				s.fail(fmt.Errorf("invalid stream status"))
				return
			}
			s.stateMu.Lock()
			if s.remoteStatus != nil {
				s.stateMu.Unlock()
				s.fail(fmt.Errorf("duplicate stream status"))
				return
			}
			if value.OK && (!s.localFin || !s.remoteFin || !s.localFinAck) {
				s.stateMu.Unlock()
				s.fail(fmt.Errorf("success status before stream FIN completion"))
				return
			}
			s.remoteStatus = &value
			s.stateMu.Unlock()
			close(s.remoteStatCh)
			if !s.queueStatusAck() {
				return
			}
			if !value.OK {
				s.fail(errors.New(value.Error))
				return
			}
		case msgStatusAck:
			if len(data) != 0 {
				s.fail(fmt.Errorf("invalid stream status acknowledgement"))
				return
			}
			s.stateMu.Lock()
			if !s.localStatus || s.localStatusAck {
				s.stateMu.Unlock()
				s.fail(fmt.Errorf("unexpected stream status acknowledgement"))
				return
			}
			s.localStatusAck = true
			s.stateMu.Unlock()
			close(s.localStatAckCh)
		case msgAbort:
			s.fail(fmt.Errorf("peer aborted stream: %s", safeReason(data)))
			return
		case msgHeartbeat:
			if len(data) != 0 {
				s.fail(fmt.Errorf("invalid stream heartbeat"))
				return
			}
		case msgReady:
			if !s.isHandshaken() || len(data) != 0 {
				s.fail(fmt.Errorf("invalid stream ready"))
				return
			}
			s.stateMu.Lock()
			if s.remoteReady {
				s.stateMu.Unlock()
				s.fail(fmt.Errorf("duplicate stream ready"))
				return
			}
			s.remoteReady = true
			s.stateMu.Unlock()
			close(s.remoteReadyCh)
		default:
			s.fail(fmt.Errorf("unsupported stream frame type 0x%x", typ))
			return
		}
	}
}

func (s *Stream) heartbeats() {
	ticker := time.NewTicker(heartbeatEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if time.Since(time.Unix(0, s.lastRead.Load())) > peerIdleTimeout {
				s.fail(fmt.Errorf("stream peer heartbeat timeout"))
				return
			}
			if s.isHandshaken() {
				_ = s.queueHeartbeat()
			}
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *Stream) waitCredit() error {
	for {
		s.creditMu.Lock()
		available := s.framesSent-s.peerCredit < maxFrames
		s.creditMu.Unlock()
		if available {
			return nil
		}
		select {
		case <-s.creditNotify:
		case <-s.ctx.Done():
			return s.terminalError()
		}
	}
}

func (s *Stream) sendCredit() {
	var data [8]byte
	binary.BigEndian.PutUint64(data[:], s.framesRead)
	if err := s.send(s.ctx, msgCredit, data[:]); err != nil {
		s.fail(err)
	}
}

func (s *Stream) send(ctx context.Context, typ byte, data []byte) error {
	// A caller may reuse its Write buffer after cancellation returns before the
	// bounded physical writer dequeues this request.
	payload := append([]byte(nil), data...)
	request := writeRequest{typ: typ, data: payload, done: make(chan error, 1)}
	select {
	case s.writeCh <- request:
	case <-s.ctx.Done():
		return s.terminalError()
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-request.done:
		return err
	case <-s.ctx.Done():
		return s.terminalError()
	case <-ctx.Done():
		return ctx.Err()
	}
}

// sendStatus joins a queued terminal-status write after cancellation. The peer
// can close immediately after reading it, before the physical writer returns.
func (s *Stream) sendStatus(ctx context.Context, data []byte) error {
	payload := append([]byte(nil), data...)
	s.stateMu.Lock()
	if s.writerStopped || s.ctx.Err() != nil {
		s.stateMu.Unlock()
		return s.terminalError()
	}
	select {
	case s.writeCh <- writeRequest{typ: msgStatus, data: payload}:
		s.localStatusWriteQueued = true
		s.stateMu.Unlock()
		return s.waitStatusWrite(ctx)
	case <-s.ctx.Done():
		s.stateMu.Unlock()
		return s.terminalError()
	case <-ctx.Done():
		s.stateMu.Unlock()
		return ctx.Err()
	}
}

// writeFrames is the sole physical writer.  Encrypting here assigns counters
// in wire order and lets the frame reader keep handling controls while an I/O
// write is blocked.
func (s *Stream) writeFrames() {
	defer s.stopWriter()
	for {
		select {
		case request := <-s.writeCh:
			fired := make(chan struct{})
			timer := time.AfterFunc(s.writeTimeout, func() {
				s.closeTransport()
				close(fired)
			})
			err := s.frames.WriteFrame(request.typ, request.data)
			if !timer.Stop() {
				<-fired
				err = fmt.Errorf("stream physical write timed out after %v", s.writeTimeout)
			}
			if err != nil {
				if request.typ == msgStatus {
					s.completeStatusWrite(err)
				}
				if request.typ == msgStatusAck {
					s.completeStatusAckWrite(fmt.Errorf("writing stream status acknowledgement: %w", err))
				}
				if request.done != nil {
					request.done <- err
				}
				s.fail(fmt.Errorf("writing stream frame: %w", err))
				return
			}
			if request.typ == msgStatus {
				s.completeStatusWrite(nil)
			}
			if request.typ == msgStatusAck {
				s.completeStatusAckWrite(nil)
			}
			if request.done != nil {
				request.done <- nil
			}
		case <-s.ctx.Done():
			return
		}
	}
}

// queueControl is used by the reader for acknowledgements. It never waits for
// a stalled physical writer, leaving that reader free to process later control
// frames. A full bounded control queue is a protocol failure.
func (s *Stream) queueControl(typ byte, data []byte) bool {
	select {
	case s.writeCh <- writeRequest{typ: typ, data: data}:
		return true
	case <-s.ctx.Done():
		return false
	default:
		s.fail(fmt.Errorf("stream control queue overflow"))
		return false
	}
}

// queueStatusAck queues the terminal receipt. The physical writer records its
// completion synchronously so Finish can safely join it after peer EOF.
func (s *Stream) queueStatusAck() bool {
	s.stateMu.Lock()
	if s.writerStopped || s.ctx.Err() != nil {
		s.stateMu.Unlock()
		return false
	}
	select {
	case s.writeCh <- writeRequest{typ: msgStatusAck}:
		s.remoteStatAckQueued = true
		s.stateMu.Unlock()
		return true
	default:
		s.stateMu.Unlock()
		s.fail(fmt.Errorf("stream control queue overflow"))
		return false
	}
}

func (s *Stream) completeStatusAckWrite(err error) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.completeStatusAckWriteLocked(err)
}

func (s *Stream) completeStatusWrite(err error) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.completeStatusWriteLocked(err)
}

func (s *Stream) completeStatusWriteLocked(err error) {
	if !s.localStatusWriteQueued || s.localStatusWriteCompleted {
		return
	}
	s.localStatusWriteCompleted = true
	s.localStatusWriteErr = err
	close(s.localStatusWriteDoneCh)
}

func (s *Stream) completeStatusAckWriteLocked(err error) {
	if !s.remoteStatAckQueued || s.remoteStatAckCompleted {
		return
	}
	s.remoteStatAckCompleted = true
	if err == nil {
		close(s.remoteStatAckWrittenCh)
	} else {
		s.remoteStatAckWriteErr = err
	}
	close(s.remoteStatAckWriteDoneCh)
}

func (s *Stream) stopWriter() {
	err := s.terminalError()
	s.stateMu.Lock()
	s.writerStopped = true
	s.completeStatusWriteLocked(err)
	s.completeStatusAckWriteLocked(err)
	s.stateMu.Unlock()
}

func (s *Stream) queueHeartbeat() bool {
	select {
	case s.writeCh <- writeRequest{typ: msgHeartbeat}:
		return true
	case <-s.ctx.Done():
		return false
	default:
		return false
	}
}

func (s *Stream) waitGraceful(ctx context.Context) error {
	s.stateMu.Lock()
	localFin := s.localFin
	s.stateMu.Unlock()
	if !localFin {
		return fmt.Errorf("Finish(nil) requires CloseWrite")
	}
	if err := s.waitGracefulStep(ctx, s.localAckCh); err != nil {
		return err
	}
	if err := s.waitGracefulStep(ctx, s.remoteFinCh); err != nil {
		return err
	}
	if err := s.waitGracefulStep(ctx, s.remoteDrainCh); err != nil {
		return err
	}
	return nil
}

func (s *Stream) waitGracefulStep(ctx context.Context, done <-chan struct{}) error {
	statusCh := s.remoteStatCh
	for {
		select {
		case <-done:
			return nil
		case <-statusCh:
			if err := s.remoteCompletionError(); err != nil {
				return err
			}
			// A success status does not replace directional FIN completion.
			statusCh = nil
		case <-ctx.Done():
			select {
			case <-done:
				return nil
			case <-statusCh:
				if err := s.remoteCompletionError(); err != nil {
					return err
				}
				return s.terminalError()
			default:
				return s.terminalError()
			}
		}
	}
}

func (s *Stream) isHandshaken() bool {
	s.handshakeMu.Lock()
	defer s.handshakeMu.Unlock()
	return s.handshaken
}

func (s *Stream) notifyCredit() {
	select {
	case s.creditNotify <- struct{}{}:
	default:
	}
}

func (s *Stream) closeData() { s.dataCloseOnce.Do(func() { close(s.dataCh) }) }

func (s *Stream) fail(err error) {
	if err == nil {
		err = io.ErrUnexpectedEOF
	}
	s.stateMu.Lock()
	if s.terminalErr == nil {
		s.terminalErr = err
	}
	s.stateMu.Unlock()
	s.cancel()
}

func (s *Stream) terminalError() error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.terminalErr != nil {
		return s.terminalErr
	}
	return context.Canceled
}

func (s *Stream) remoteCompletionError() error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.remoteStatus == nil {
		if s.terminalErr != nil {
			return s.terminalErr
		}
		return fmt.Errorf("missing remote stream status")
	}
	if s.remoteStatus.OK {
		if s.terminalErr != nil && !isTransportEOF(s.terminalErr) {
			return s.terminalErr
		}
		return nil
	}
	return errors.New(s.remoteStatus.Error)
}

func isTransportEOF(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed)
}

func (s *Stream) closeTransport() {
	if s.closer != nil {
		_ = s.closer.Close()
	}
}

func (s *Stream) cancelTransportAtDeadline(ctx context.Context) func() {
	deadline, ok := s.closer.(interface{ SetDeadline(time.Time) error })
	if !ok {
		fired := make(chan struct{})
		stop := context.AfterFunc(ctx, func() { s.closeTransport(); close(fired) })
		return func() {
			if !stop() {
				<-fired
			}
		}
	}
	fired := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = deadline.SetDeadline(time.Now()); close(fired) })
	return func() {
		if !stop() {
			<-fired
		}
		_ = deadline.SetDeadline(time.Time{})
	}
}

func validateHello(value hello, cfg Config) error {
	if value.Protocol != protocolName {
		return fmt.Errorf("unsupported stream protocol %q", value.Protocol)
	}
	if value.Service == "" || value.Mode == "" {
		return fmt.Errorf("peer omitted stream service or mode")
	}
	if value.MaxData != maxDataSize || value.MaxOutstanding != maxFrames {
		return fmt.Errorf("incompatible stream limits")
	}
	if cfg.ExpectedService != "" && value.Service != cfg.ExpectedService {
		return fmt.Errorf("peer requested service %q, expected %q", value.Service, cfg.ExpectedService)
	}
	if cfg.ExpectedMode != "" && value.Mode != cfg.ExpectedMode {
		return fmt.Errorf("peer requested mode %q, expected %q", value.Mode, cfg.ExpectedMode)
	}
	return nil
}

func mustJSON(value any) []byte { data, _ := json.Marshal(value); return data }

func limitedError(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	if len(text) > 1024 {
		return text[:1024]
	}
	return text
}
func safeReason(data []byte) string {
	if len(data) == 0 {
		return "unspecified"
	}
	if len(data) > 1024 {
		data = data[:1024]
	}
	return string(data)
}

var _ io.ReadWriteCloser = (*Stream)(nil)
