// SPDX-License-Identifier: MIT

package transfer_test

import (
	"fmt"
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
}
