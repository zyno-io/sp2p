// SPDX-License-Identifier: MIT

package flow

import (
	"bytes"
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
		msgType, echo, err := frw.ReadFrame()
		if err != nil {
			return 0, fmt.Errorf("reading RTT probe echo: %w", err)
		}
		if msgType != transfer.MsgParallelProbe || !bytes.Equal(echo, buf[:]) {
			return 0, fmt.Errorf("unexpected message during RTT probe: 0x%02x", msgType)
		}
		rtts = append(rtts, time.Since(now))
	}
	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	return rtts[len(rtts)/2], nil
}

// negotiateSender runs the sender side of parallel TCP negotiation.
// Called after key confirmation when both sides advertised ParallelTCPV3.
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

	primaryConn.SetDeadline(time.Now().Add(parallelProbeTimeout))
	stop := context.AfterFunc(ctx, func() { primaryConn.Close() })
	defer stop()
	defer primaryConn.SetDeadline(time.Time{})

	ourCount := 1
	if fileSize >= parallelMinFileSize || parallel > 0 {
		rtt, err := probeRTTSender(encStream)
		if err != nil {
			return nil, nil, err
		}
		ourCount = resolveParallelCount(parallel, rtt)
	}
	if ourCount < 1 || ourCount > 6 {
		return nil, nil, fmt.Errorf("invalid parallel count: %d", ourCount)
	}
	if err := encStream.WriteFrame(transfer.MsgParallelReady, []byte{byte(ourCount)}); err != nil {
		return nil, nil, fmt.Errorf("sending parallel count: %w", err)
	}
	msgType, data, err := encStream.ReadFrame()
	if err != nil {
		return nil, nil, fmt.Errorf("reading parallel count: %w", err)
	}
	peerCount, err := parseParallelCount(msgType, data)
	if err != nil {
		return nil, nil, err
	}
	agreed := min(ourCount, peerCount)
	if agreed == 1 {
		return encStream, primaryConn, nil
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

	primaryConn.SetDeadline(time.Now().Add(parallelProbeTimeout))
	stop := context.AfterFunc(ctx, func() { primaryConn.Close() })
	defer stop()
	defer primaryConn.SetDeadline(time.Time{})

	msgType, data, err := encStream.ReadFrame()
	if err != nil {
		return nil, nil, fmt.Errorf("reading parallel negotiation: %w", err)
	}
	if msgType == transfer.MsgParallelProbe {
		for i := 0; i < parallelProbeCount; i++ {
			if msgType != transfer.MsgParallelProbe || len(data) != 8 {
				return nil, nil, fmt.Errorf("invalid parallel probe")
			}
			if err := encStream.WriteFrame(transfer.MsgParallelProbe, data); err != nil {
				return nil, nil, fmt.Errorf("echoing parallel probe: %w", err)
			}
			msgType, data, err = encStream.ReadFrame()
			if err != nil {
				return nil, nil, fmt.Errorf("reading parallel negotiation: %w", err)
			}
		}
	}
	senderCount, err := parseParallelCount(msgType, data)
	if err != nil {
		return nil, nil, err
	}
	ourCount := 6
	if parallel > 0 {
		ourCount = parallel
	}
	if ourCount < 1 || ourCount > 6 {
		return nil, nil, fmt.Errorf("invalid parallel count: %d", ourCount)
	}
	if err := encStream.WriteFrame(transfer.MsgParallelReady, []byte{byte(ourCount)}); err != nil {
		return nil, nil, fmt.Errorf("sending parallel count: %w", err)
	}
	agreed := min(senderCount, ourCount)
	if agreed == 1 {
		return encStream, primaryConn, nil
	}
	return setupSecondary(ctx, encStream, primaryConn, tcpResult, sharedSecret, seed, agreed, false, sessionID, senderPub, receiverPub, onLog)
}

func parseParallelCount(kind byte, data []byte) (int, error) {
	if kind != transfer.MsgParallelReady || len(data) != 1 || data[0] < 1 || data[0] > 6 {
		return 0, fmt.Errorf("invalid parallel count frame")
	}
	return int(data[0]), nil
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
		return nil, nil, fmt.Errorf("deriving parallel token: %w", err)
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
		return nil, nil, fmt.Errorf("sending actual stream count: %w", werr)
	}
	msgType, data, err := encStream.ReadFrame()
	primaryConn.SetDeadline(time.Time{})
	if err != nil {
		for _, c := range secondaryConns {
			c.Close()
		}
		return nil, nil, fmt.Errorf("reading actual stream count: %w", err)
	}
	peerActual, err := parseParallelCount(msgType, data)
	if err != nil || (peerActual != 1 && peerActual != agreed) {
		for _, c := range secondaryConns {
			c.Close()
		}
		return nil, nil, fmt.Errorf("invalid actual parallel stream count")
	}

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
			return nil, nil, fmt.Errorf("deriving parallel keys: %w", kerr)
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
			return nil, nil, fmt.Errorf("creating secondary encrypted stream: %w", serr)
		}
		streams[i+1] = es
		conns[i+1] = sc
	}

	ms := transfer.NewMultiStream(streams, conns)
	return ms, ms, nil
}
