// SPDX-License-Identifier: MIT

package flow

import (
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"time"

	"github.com/zyno-io/sp2p/internal/conn"
	"github.com/zyno-io/sp2p/internal/crypto"
	"github.com/zyno-io/sp2p/internal/transfer"
)

const (
	// parallelMinFileSize is the minimum file size to consider parallel TCP.
	parallelMinFileSize = 64 * 1024 * 1024 // 64 MiB

	// parallelProbeCount is how many RTT probes to send.
	parallelProbeCount = 3

	// parallelProbeTimeout is the max time for the entire RTT probe phase.
	parallelProbeTimeout = 5 * time.Second

	// parallelSecondaryTimeout is the timeout for establishing secondary connections.
	parallelSecondaryTimeout = 5 * time.Second
)

// parallelCountForRTT returns the number of TCP connections to use based on
// the measured median RTT.
func parallelCountForRTT(medianRTT time.Duration) int {
	switch {
	case medianRTT < 5*time.Millisecond:
		return 1
	case medianRTT < 20*time.Millisecond:
		return 2
	case medianRTT < 50*time.Millisecond:
		return 3
	case medianRTT < 100*time.Millisecond:
		return 4
	default:
		return 6
	}
}

// resolveParallelCount determines the desired parallel connection count.
// userOverride: 0=auto (RTT-based), 1=single, 2-6=force.
func resolveParallelCount(userOverride int, medianRTT time.Duration) int {
	if userOverride > 0 {
		return userOverride
	}
	return parallelCountForRTT(medianRTT)
}

// probeRTTSender sends RTT probes and measures median RTT.
func probeRTTSender(frw transfer.FrameReadWriter) (time.Duration, error) {
	rtts := make([]time.Duration, 0, parallelProbeCount)
	for range parallelProbeCount {
		var buf [8]byte
		now := time.Now()
		binary.BigEndian.PutUint64(buf[:], uint64(now.UnixNano()))
		if err := frw.WriteFrame(transfer.MsgParallelProbe, buf[:]); err != nil {
			return 0, fmt.Errorf("writing RTT probe: %w", err)
		}
		msgType, _, err := frw.ReadFrame()
		if err != nil {
			return 0, fmt.Errorf("reading RTT probe echo: %w", err)
		}
		if msgType != transfer.MsgParallelProbe {
			return 0, fmt.Errorf("unexpected message during RTT probe: 0x%02x", msgType)
		}
		rtts = append(rtts, time.Since(now))
	}
	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	return rtts[len(rtts)/2], nil
}

// negotiateSender runs the sender side of parallel TCP negotiation.
// Called after key confirmation when both sides advertised ParallelTCP.
// If the file is too small or probes indicate no benefit, returns the
// original single-stream setup.
func negotiateSender(
	ctx context.Context,
	encStream *crypto.EncryptedStream,
	primaryConn conn.P2PConn,
	tcpResult *conn.TCPResult,
	sharedSecret, seed []byte,
	fileSize uint64,
	parallel int,
	sessionID string,
	senderPub, receiverPub []byte,
	onLog func(string),
) (transfer.FrameReadWriter, transfer.DeadlineSetter, error) {
	single := func() (transfer.FrameReadWriter, transfer.DeadlineSetter, error) {
		return encStream, primaryConn, nil
	}

	// Set a deadline on the primary connection for the negotiation phase
	// so we don't block indefinitely on probe/ready I/O.
	primaryConn.SetDeadline(time.Now().Add(parallelProbeTimeout))
	defer primaryConn.SetDeadline(time.Time{}) // clear after negotiation

	// If file is too small (and not forced), skip probes, just send count=1.
	if fileSize < parallelMinFileSize && parallel == 0 {
		logVerbose(onLog, "file too small for parallel TCP (%d bytes < %d), sending count=1", fileSize, parallelMinFileSize)
		if err := encStream.WriteFrame(transfer.MsgParallelReady, []byte{1}); err != nil {
			return single()
		}
		// Read receiver's response (they'll send their count, but we'll min with 1).
		msgType, _, err := encStream.ReadFrame()
		if err != nil || msgType != transfer.MsgParallelReady {
			return single()
		}
		return single()
	}

	// RTT probe.
	rtt, err := probeRTTSender(encStream)
	if err != nil {
		// Send count=1 so the receiver's negotiation loop has a clean
		// exit (it handles MsgParallelReady arriving mid-probe).
		logVerbose(onLog, "RTT probe failed: %v — sending count=1", err)
		encStream.WriteFrame(transfer.MsgParallelReady, []byte{1})
		// Best-effort drain: read frames until we get the receiver's
		// MsgParallelReady response (or hit the deadline). This
		// consumes any lingering probe echoes that the receiver may
		// have already sent, preventing them from being misinterpreted
		// as transfer protocol frames. The deadline set at the top of
		// negotiateSender bounds this loop to parallelProbeTimeout.
		for {
			msgType, _, rerr := encStream.ReadFrame()
			if rerr != nil || msgType == transfer.MsgParallelReady {
				break
			}
		}
		return single()
	}
	logVerbose(onLog, "RTT probe: median=%v", rtt)

	ourCount := resolveParallelCount(parallel, rtt)

	// Exchange counts.
	if err := encStream.WriteFrame(transfer.MsgParallelReady, []byte{byte(ourCount)}); err != nil {
		return single()
	}
	msgType, data, err := encStream.ReadFrame()
	if err != nil || msgType != transfer.MsgParallelReady || len(data) < 1 {
		return single()
	}
	peerCount := int(data[0])
	agreed := min(ourCount, peerCount)
	logVerbose(onLog, "parallel negotiation: ours=%d, peer=%d, agreed=%d", ourCount, peerCount, agreed)

	if agreed <= 1 {
		return single()
	}

	return setupSecondary(ctx, encStream, primaryConn, tcpResult, sharedSecret, seed, agreed, true, sessionID, senderPub, receiverPub, onLog)
}

// negotiateReceiver runs the receiver side of parallel TCP negotiation.
// It echoes RTT probes (if sent), then exchanges counts. The first frame
// after key confirmation will be either MsgParallelProbe (probes coming)
// or MsgParallelReady (no probes, sender's count).
func negotiateReceiver(
	ctx context.Context,
	encStream *crypto.EncryptedStream,
	primaryConn conn.P2PConn,
	tcpResult *conn.TCPResult,
	sharedSecret, seed []byte,
	parallel int,
	sessionID string,
	senderPub, receiverPub []byte,
	onLog func(string),
) (transfer.FrameReadWriter, transfer.DeadlineSetter, error) {
	single := func() (transfer.FrameReadWriter, transfer.DeadlineSetter, error) {
		return encStream, primaryConn, nil
	}

	// Set a deadline on the primary connection for the negotiation phase.
	primaryConn.SetDeadline(time.Now().Add(parallelProbeTimeout))
	defer primaryConn.SetDeadline(time.Time{}) // clear after negotiation

	// Read the first frame — it's either a probe or a ParallelReady.
	msgType, data, err := encStream.ReadFrame()
	if err != nil {
		return single()
	}

	if msgType == transfer.MsgParallelProbe {
		// Echo this probe and the remaining ones.
		if err := encStream.WriteFrame(transfer.MsgParallelProbe, data); err != nil {
			return single()
		}
		for range parallelProbeCount - 1 {
			msgType, data, err = encStream.ReadFrame()
			if err != nil {
				return single()
			}
			if msgType == transfer.MsgParallelReady && len(data) >= 1 {
				// Sender's probes failed mid-sequence; it sent
				// MsgParallelReady(1) to exit cleanly. Respond
				// in kind so the sender's ReadFrame unblocks.
				logVerbose(onLog, "sender cut probes short, received ParallelReady with count=%d", data[0])
				encStream.WriteFrame(transfer.MsgParallelReady, []byte{1})
				return single()
			}
			if msgType != transfer.MsgParallelProbe {
				logVerbose(onLog, "unexpected frame during probe echo: 0x%02x", msgType)
				encStream.WriteFrame(transfer.MsgParallelReady, []byte{1})
				return single()
			}
			if err := encStream.WriteFrame(transfer.MsgParallelProbe, data); err != nil {
				return single()
			}
		}
		// Now read the ParallelReady.
		msgType, data, err = encStream.ReadFrame()
		if err != nil || msgType != transfer.MsgParallelReady || len(data) < 1 {
			return single()
		}
	} else if msgType != transfer.MsgParallelReady || len(data) < 1 {
		logVerbose(onLog, "unexpected first frame during parallel negotiation: 0x%02x", msgType)
		encStream.WriteFrame(transfer.MsgParallelReady, []byte{1})
		return single()
	}

	senderCount := int(data[0])

	// Determine our count (receiver defaults to max to let sender decide).
	ourCount := 6
	if parallel > 0 {
		ourCount = parallel
	}
	if err := encStream.WriteFrame(transfer.MsgParallelReady, []byte{byte(ourCount)}); err != nil {
		return single()
	}

	agreed := min(senderCount, ourCount)
	logVerbose(onLog, "parallel negotiation: sender=%d, ours=%d, agreed=%d", senderCount, ourCount, agreed)

	if agreed <= 1 {
		return single()
	}

	return setupSecondary(ctx, encStream, primaryConn, tcpResult, sharedSecret, seed, agreed, false, sessionID, senderPub, receiverPub, onLog)
}

// setupSecondary establishes secondary connections and creates a MultiStream.
func setupSecondary(
	ctx context.Context,
	encStream *crypto.EncryptedStream,
	primaryConn conn.P2PConn,
	tcpResult *conn.TCPResult,
	sharedSecret, seed []byte,
	agreed int,
	isSender bool,
	sessionID string,
	senderPub, receiverPub []byte,
	onLog func(string),
) (transfer.FrameReadWriter, transfer.DeadlineSetter, error) {
	single := func() (transfer.FrameReadWriter, transfer.DeadlineSetter, error) {
		return encStream, primaryConn, nil
	}

	token, err := crypto.DeriveParallelToken(sharedSecret, seed, sessionID, senderPub, receiverPub)
	if err != nil {
		logVerbose(onLog, "failed to derive parallel token: %v", err)
		return single()
	}

	secondaryConns, err := conn.EstablishSecondary(ctx, conn.SecondaryConfig{
		Count:         agreed - 1,
		WeDialed:      tcpResult.WeDialed,
		Listener:      tcpResult.Listener,
		PeerAddr:      tcpResult.PeerAddr,
		Token:         token,
		Timeout:       parallelSecondaryTimeout,
		AcceptStopped: tcpResult.AcceptStopped,
		OnLog:         onLog,
	})

	ourActual := 1
	if err != nil {
		logVerbose(onLog, "secondary connections failed: %v", err)
	} else {
		ourActual = 1 + len(secondaryConns)
	}

	// Synchronize actual stream count with peer. Both sides must agree on
	// the exact same count — if counts differ, the connection subsets may
	// not match (partial failures leave different dense orderings), which
	// would cause key derivation mismatches. Fall back to single-stream
	// unless both sides established exactly the same number.
	primaryConn.SetDeadline(time.Now().Add(parallelSecondaryTimeout))
	if werr := encStream.WriteFrame(transfer.MsgParallelReady, []byte{byte(ourActual)}); werr != nil {
		for _, c := range secondaryConns {
			c.Close()
		}
		primaryConn.SetDeadline(time.Time{})
		return single()
	}
	msgType, data, err := encStream.ReadFrame()
	primaryConn.SetDeadline(time.Time{})
	if err != nil || msgType != transfer.MsgParallelReady || len(data) < 1 {
		for _, c := range secondaryConns {
			c.Close()
		}
		return single()
	}
	peerActual := int(data[0])

	// Require exact match — partial success with different subsets leads to
	// key/stream mismatch since dense compaction loses original indices.
	if ourActual != peerActual || ourActual <= 1 {
		if ourActual != peerActual {
			logVerbose(onLog, "parallel stream count mismatch (ours=%d, peer=%d) — using single connection", ourActual, peerActual)
		}
		for _, c := range secondaryConns {
			c.Close()
		}
		return single()
	}

	totalStreams := ourActual
	logVerbose(onLog, "established %d parallel TCP connections", totalStreams)

	streams := make([]transfer.FrameReadWriter, totalStreams)
	conns := make([]transfer.MultiStreamConn, totalStreams)
	streams[0] = encStream
	conns[0] = primaryConn

	for i, sc := range secondaryConns {
		s2rKey, r2sKey, kerr := crypto.DeriveParallelKeys(sharedSecret, seed, i+1, sessionID, senderPub, receiverPub)
		if kerr != nil {
			// Close already-wrapped connections (indices 0..i-1).
			for j := 0; j < i; j++ {
				secondaryConns[j].Close()
			}
			// Close unwrapped connections (indices i..N-1).
			for j := i; j < len(secondaryConns); j++ {
				secondaryConns[j].Close()
			}
			logVerbose(onLog, "failed to derive parallel keys: %v", kerr)
			return single()
		}

		var writeKey, readKey []byte
		if isSender {
			writeKey, readKey = s2rKey, r2sKey
		} else {
			writeKey, readKey = r2sKey, s2rKey
		}

		es, serr := crypto.NewEncryptedStream(sc, writeKey, readKey)
		if serr != nil {
			// Close already-wrapped connections (indices 0..i-1).
			for j := 0; j < i; j++ {
				secondaryConns[j].Close()
			}
			// Close unwrapped connections (indices i..N-1).
			for j := i; j < len(secondaryConns); j++ {
				secondaryConns[j].Close()
			}
			logVerbose(onLog, "failed to create secondary encrypted stream: %v", serr)
			return single()
		}
		streams[i+1] = es
		conns[i+1] = sc
	}

	ms := transfer.NewMultiStream(streams, conns)
	return ms, ms, nil
}
