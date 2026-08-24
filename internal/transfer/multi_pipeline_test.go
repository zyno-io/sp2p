// SPDX-License-Identifier: MIT

package transfer_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/zyno-io/sp2p/internal/crypto"
	"github.com/zyno-io/sp2p/internal/transfer"
)

// tcpTestConn wraps net.Conn to satisfy transfer.MultiStreamConn.
type tcpTestConn struct {
	net.Conn
}

func (c *tcpTestConn) SetDeadline(t time.Time) error { return c.Conn.SetDeadline(t) }
func (c *tcpTestConn) Close() error                  { return c.Conn.Close() }

// gatedTCPTestConn blocks reads until gate is closed. It simulates a slower
// secondary TCP stream without delaying the primary stream's Done frame.
type gatedTCPTestConn struct {
	*tcpTestConn
	gate <-chan struct{}
}

func (c *gatedTCPTestConn) Read(p []byte) (int, error) {
	<-c.gate
	return c.tcpTestConn.Read(p)
}

func newTCPPair(t *testing.T) (*tcpTestConn, *tcpTestConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	acceptCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		acceptCh <- c
	}()
	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	c2 := <-acceptCh
	return &tcpTestConn{c1}, &tcpTestConn{c2}
}

// TestMultiStreamPipelinedPath exercises the ReserveWriteSeq / PrepareFrameAt /
// WriteRawFrame pipeline through MultiStream with real EncryptedStream instances.
func TestMultiStreamPipelinedPath(t *testing.T) {
	const numStreams = 2
	const numChunks = 10

	senderStreams := make([]transfer.FrameReadWriter, numStreams)
	receiverStreams := make([]transfer.FrameReadWriter, numStreams)
	senderConns := make([]transfer.MultiStreamConn, numStreams)
	receiverConns := make([]transfer.MultiStreamConn, numStreams)

	for i := range numStreams {
		sConn, rConn := newTCPPair(t)
		s2rKey := make([]byte, 32)
		r2sKey := make([]byte, 32)
		for j := range 32 {
			s2rKey[j] = byte(i*64 + j + 0x10)
			r2sKey[j] = byte(i*64 + j + 0x30)
		}
		sES, err := crypto.NewEncryptedStream(sConn, s2rKey, r2sKey)
		if err != nil {
			t.Fatalf("sender EncryptedStream %d: %v", i, err)
		}
		rES, err := crypto.NewEncryptedStream(rConn, r2sKey, s2rKey)
		if err != nil {
			t.Fatalf("receiver EncryptedStream %d: %v", i, err)
		}
		senderStreams[i] = sES
		receiverStreams[i] = rES
		senderConns[i] = sConn
		receiverConns[i] = rConn
	}

	msSender := transfer.NewMultiStream(senderStreams, senderConns)
	msReceiver := transfer.NewMultiStream(receiverStreams, receiverConns)
	defer msSender.Close()
	defer msReceiver.Close()

	// Verify MultiStream implements ParallelFramePreparer.
	pp, ok := interface{}(msSender).(transfer.ParallelFramePreparer)
	if !ok {
		t.Fatal("MultiStream does not implement ParallelFramePreparer")
	}

	// Pipeline: reserve all, prepare all, then write all in order.
	seqs := make([]uint64, numChunks)
	for i := range numChunks {
		seq, err := pp.ReserveWriteSeq()
		if err != nil {
			t.Fatalf("ReserveWriteSeq %d: %v", i, err)
		}
		seqs[i] = seq
	}

	frames := make([][]byte, numChunks)
	for i := range numChunks {
		payload := []byte(fmt.Sprintf("pipelined-%03d", i))
		frame, err := pp.PrepareFrameAt(transfer.MsgData, payload, seqs[i])
		if err != nil {
			t.Fatalf("PrepareFrameAt %d: %v", i, err)
		}
		frames[i] = frame
	}

	// Write in order.
	for i, frame := range frames {
		if err := pp.WriteRawFrame(frame); err != nil {
			t.Fatalf("WriteRawFrame %d: %v", i, err)
		}
	}
	if err := msSender.WriteFrame(transfer.MsgDone, []byte(fmt.Sprintf(`{"chunkCount":%d}`, numChunks))); err != nil {
		t.Fatalf("WriteFrame done: %v", err)
	}

	// Read and verify order on receiver side.
	for i := range numChunks {
		msgType, data, err := msReceiver.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame %d: %v", i, err)
		}
		if msgType != transfer.MsgData {
			t.Fatalf("chunk %d: expected MsgData, got 0x%02x", i, msgType)
		}
		expected := fmt.Sprintf("pipelined-%03d", i)
		if string(data) != expected {
			t.Fatalf("chunk %d: expected %q, got %q", i, expected, string(data))
		}
	}

	msgType, _, err := msReceiver.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame done: %v", err)
	}
	if msgType != transfer.MsgDone {
		t.Fatalf("expected MsgDone, got 0x%02x", msgType)
	}
}

// TestMultiStreamPipelinedTransferWaitsForSecondaryTail exercises the full
// Sender/Receiver pipelined path while a secondary stream's final chunk is
// delayed past Done on the primary stream.
func TestMultiStreamPipelinedTransferWaitsForSecondaryTail(t *testing.T) {
	const numStreams = 2

	senderStreams := make([]transfer.FrameReadWriter, numStreams)
	receiverStreams := make([]transfer.FrameReadWriter, numStreams)
	senderConns := make([]transfer.MultiStreamConn, numStreams)
	receiverConns := make([]transfer.MultiStreamConn, numStreams)
	secondaryGate := make(chan struct{})
	gateClosed := false
	defer func() {
		if !gateClosed {
			close(secondaryGate)
		}
	}()

	for i := range numStreams {
		sConn, rConn := newTCPPair(t)
		s2rKey := make([]byte, 32)
		r2sKey := make([]byte, 32)
		for j := range 32 {
			s2rKey[j] = byte(i*64 + j + 0x10)
			r2sKey[j] = byte(i*64 + j + 0x30)
		}
		sES, err := crypto.NewEncryptedStream(sConn, s2rKey, r2sKey)
		if err != nil {
			t.Fatalf("sender EncryptedStream %d: %v", i, err)
		}

		var receiverRaw io.ReadWriter = rConn
		var receiverConn transfer.MultiStreamConn = rConn
		if i == 1 {
			gatedConn := &gatedTCPTestConn{tcpTestConn: rConn, gate: secondaryGate}
			receiverRaw = gatedConn
			receiverConn = gatedConn
		}
		rES, err := crypto.NewEncryptedStream(receiverRaw, r2sKey, s2rKey)
		if err != nil {
			t.Fatalf("receiver EncryptedStream %d: %v", i, err)
		}
		senderStreams[i] = sES
		receiverStreams[i] = rES
		senderConns[i] = sConn
		receiverConns[i] = receiverConn
	}

	msSender := transfer.NewMultiStream(senderStreams, senderConns)
	msReceiver := transfer.NewMultiStream(receiverStreams, receiverConns)
	defer msSender.Close()
	defer msReceiver.Close()

	payload := bytes.Repeat([]byte{0x7f}, transfer.MaxChunkSize+1)
	meta := &transfer.Metadata{Name: "tail.bin", Size: uint64(len(payload))}
	sender := transfer.NewSender(msSender, meta)
	receiver := transfer.NewReceiver(msReceiver)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sendCh := make(chan error, 1)
	go func() {
		sendCh <- sender.Send(ctx, bytes.NewReader(payload), nil)
	}()

	type receiveResult struct {
		data []byte
		err  error
	}
	receiveCh := make(chan receiveResult, 1)
	go func() {
		var output bytes.Buffer
		_, err := receiver.Receive(ctx, &output, nil)
		receiveCh <- receiveResult{data: output.Bytes(), err: err}
	}()

	select {
	case result := <-receiveCh:
		t.Fatalf("receiver completed before delayed chunk arrived: %v", result.err)
	case err := <-sendCh:
		t.Fatalf("sender completed before delayed chunk arrived: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(secondaryGate)
	gateClosed = true

	select {
	case result := <-receiveCh:
		if result.err != nil {
			t.Fatalf("receiver failed: %v", result.err)
		}
		if !bytes.Equal(result.data, payload) {
			t.Fatal("receiver payload mismatch")
		}
	case <-ctx.Done():
		t.Fatalf("receiver did not finish: %v", ctx.Err())
	}

	select {
	case err := <-sendCh:
		if err != nil {
			t.Fatalf("sender failed: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("sender did not finish: %v", ctx.Err())
	}
}
