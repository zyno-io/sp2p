// SPDX-License-Identifier: MIT

package transfer

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// Message types for the transfer protocol.
const (
	MsgMetadata      = 0x01
	MsgData          = 0x02
	MsgDone          = 0x04
	MsgComplete      = 0x05
	MsgError         = 0x06
	MsgFinAck        = 0x07
	MsgHeartbeat     = 0x08
	MsgCancel        = 0x09
	MsgParallelProbe = 0x0A // RTT probe: sender sends, receiver echoes
	MsgParallelReady = 0x0B // Parallel count negotiation frame
)

// Cancel reason codes.
const (
	CancelUserAbort byte = 0x01 // User cancelled (Ctrl+C, tab close)
	CancelError     byte = 0x02 // Internal error
)

const (
	// MaxChunkSize is the maximum data chunk size (256 KiB).
	MaxChunkSize = 256 * 1024
	// MaxFrameSize is the maximum frame payload size (512 KiB, accounts for encryption overhead).
	MaxFrameSize = 512 * 1024
	// MaxControlSize is the maximum size for non-data frames (4 KiB).
	MaxControlSize = 4 * 1024
	// FrameHeaderSize is the 4-byte length prefix.
	FrameHeaderSize = 4
)

// Metadata describes the file being transferred.
type Metadata struct {
	Name        string `json:"name"`
	Size        uint64 `json:"size"`                  // 0 for streams
	Type        string `json:"type"`                  // MIME type
	IsFolder    bool   `json:"isFolder"`
	StreamMode  bool   `json:"streamMode"`
	FileCount   int    `json:"fileCount,omitempty"`   // number of files (for folders/multi-file sends)
	Compression string `json:"compression,omitempty"` // compression algorithm (e.g. "zstd")
}

// Done signals transfer completion with verification data.
type Done struct {
	TotalBytes uint64 `json:"totalBytes"`
	ChunkCount uint64 `json:"chunkCount"`
	SHA256     string `json:"sha256"` // hex-encoded SHA-256 of all data chunks
}

// Complete signals receiver verification.
type Complete struct {
	TotalBytes uint64 `json:"totalBytes"`
	ChunkCount uint64 `json:"chunkCount"`
	SHA256     string `json:"sha256"` // hex-encoded SHA-256 (echoed back for confirmation)
}

// TransferError carries an error message.
type TransferError struct {
	Message string `json:"message"`
}

// FrameReadWriter is the interface for sending/receiving typed frames.
// Implementations handle encryption transparently.
type FrameReadWriter interface {
	WriteFrame(msgType byte, data []byte) error
	ReadFrame() (msgType byte, data []byte, err error)
}

// FramePreparer is an optional interface for FrameReadWriters that can
// separate frame preparation (e.g. encryption) from the actual write.
// This enables pipelining: a producer can prepare frames while the
// writer goroutine flushes previously prepared frames to the network.
type FramePreparer interface {
	PrepareFrame(msgType byte, data []byte) ([]byte, error)
	WriteRawFrame(frame []byte) error
}

// ParallelFramePreparer extends FramePreparer with methods for parallel
// encryption. ReserveWriteSeq assigns sequential nonces, and PrepareFrameAt
// encrypts using a pre-assigned nonce. Multiple goroutines can call
// PrepareFrameAt concurrently with different sequence numbers, allowing
// N-way parallel compression + encryption. Frames must still be written
// in sequence order via WriteRawFrame.
type ParallelFramePreparer interface {
	FramePreparer
	ReserveWriteSeq() (uint64, error)
	PrepareFrameAt(msgType byte, data []byte, seq uint64) ([]byte, error)
}

// BufferedAmounter is implemented by connections that can report how many
// bytes are queued in their send buffer but not yet transmitted. This is
// used to adjust sender progress so it reflects actual transmission rather
// than local buffering.
type BufferedAmounter interface {
	BufferedAmount() uint64
}

// DeadlineSetter is implemented by connections that support idle deadlines.
type DeadlineSetter interface {
	SetDeadline(t time.Time) error
}

// PlaintextFrameRW implements FrameReadWriter over a raw io.ReadWriter (no encryption).
// Wire format: [4 bytes: payload length] [1 byte: type] [N bytes: data]
type PlaintextFrameRW struct {
	RW io.ReadWriter
}

func (p *PlaintextFrameRW) WriteFrame(msgType byte, data []byte) error {
	payloadLen := 1 + len(data)
	if payloadLen > MaxFrameSize {
		return fmt.Errorf("frame too large: %d > %d", payloadLen, MaxFrameSize)
	}

	// Build the full frame in one buffer to avoid partial writes.
	frame := make([]byte, FrameHeaderSize+payloadLen)
	binary.BigEndian.PutUint32(frame[0:4], uint32(payloadLen))
	frame[4] = msgType
	copy(frame[5:], data)

	_, err := writeAll(p.RW, frame)
	return err
}

// writeAll writes all of p to w, handling short writes.
func writeAll(w io.Writer, p []byte) (int, error) {
	total := 0
	for total < len(p) {
		n, err := w.Write(p[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func (p *PlaintextFrameRW) ReadFrame() (byte, []byte, error) {
	var hdr [FrameHeaderSize]byte
	if _, err := io.ReadFull(p.RW, hdr[:]); err != nil {
		return 0, nil, err
	}

	payloadLen := binary.BigEndian.Uint32(hdr[:])
	if payloadLen == 0 {
		return 0, nil, fmt.Errorf("empty frame")
	}
	if payloadLen > MaxFrameSize {
		return 0, nil, fmt.Errorf("frame too large: %d > %d", payloadLen, MaxFrameSize)
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(p.RW, payload); err != nil {
		return 0, nil, err
	}

	return payload[0], payload[1:], nil
}

// Helper functions for writing typed messages.

func WriteMetadata(frw FrameReadWriter, meta *Metadata) error {
	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return frw.WriteFrame(MsgMetadata, data)
}

func WriteData(frw FrameReadWriter, chunk []byte) error {
	return frw.WriteFrame(MsgData, chunk)
}

func WriteDone(frw FrameReadWriter, done *Done) error {
	data, err := json.Marshal(done)
	if err != nil {
		return err
	}
	return frw.WriteFrame(MsgDone, data)
}

func WriteComplete(frw FrameReadWriter, complete *Complete) error {
	data, err := json.Marshal(complete)
	if err != nil {
		return err
	}
	return frw.WriteFrame(MsgComplete, data)
}

func WriteFinAck(frw FrameReadWriter) error {
	return frw.WriteFrame(MsgFinAck, nil)
}

func WriteError(frw FrameReadWriter, message string) error {
	data, err := json.Marshal(TransferError{Message: message})
	if err != nil {
		return err
	}
	return frw.WriteFrame(MsgError, data)
}

func WriteCancel(frw FrameReadWriter, reason byte) error {
	return frw.WriteFrame(MsgCancel, []byte{reason})
}

func WriteHeartbeat(frw FrameReadWriter) error {
	return frw.WriteFrame(MsgHeartbeat, nil)
}
