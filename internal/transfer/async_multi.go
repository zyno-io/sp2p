// SPDX-License-Identifier: MIT

package transfer

import (
	"context"
	"encoding/binary"
	"sync/atomic"
)

const (
	streamWriteQueued uint32 = iota
	streamWriteStarted
	streamWriteCanceled
)

type streamWrite struct {
	kind  byte
	data  []byte
	done  chan error
	state atomic.Uint32
}
type asyncMultiWriter struct {
	queues      []chan *streamWrite
	pending     []chan error
	queuedBytes []atomic.Int64
}

// WriteSessionFrame is called only by Session's serialized dispatcher. Network
// writes have one owner per stream, so a blocked secondary cannot block writes
// on other sockets. Metadata and controls still serialize with primary data.
func (ms *MultiStream) WriteSessionFrame(ctx context.Context, kind byte, data []byte) error {
	return ms.writeSessionFrame(ctx, kind, data, func(frw FrameReadWriter, kind byte, data []byte) error {
		return frw.WriteFrame(kind, data)
	})
}

func (ms *MultiStream) writeSessionFrame(ctx context.Context, kind byte, data []byte, write func(FrameReadWriter, byte, []byte) error) error {
	if ms.asyncWriter == nil {
		w := &asyncMultiWriter{queues: make([]chan *streamWrite, ms.n), queuedBytes: make([]atomic.Int64, ms.n)}
		for i := range w.queues {
			q := make(chan *streamWrite, CreditWindow)
			w.queues[i] = q
			go func(index int) {
				for {
					// Prefer shutdown before taking another queued write. The
					// second select still handles cancellation while idle.
					select {
					case <-ctx.Done():
						return
					default:
					}
					select {
					case <-ctx.Done():
						return
					case job := <-q:
						if !job.state.CompareAndSwap(streamWriteQueued, streamWriteStarted) {
							w.queuedBytes[index].Add(-int64(len(job.data)))
							continue
						}
						err := write(ms.streams[index], job.kind, job.data)
						w.queuedBytes[index].Add(-int64(len(job.data)))
						job.done <- err
						if err != nil {
							ms.readErr.CompareAndSwap(nil, &err)
							ms.readCancel()
							ms.reassembly.abort(err)
							for _, c := range ms.conns {
								c.Close()
							}
							return
						}
					}
				}
			}(i)
		}
		ms.asyncWriter = w
	}
	w := ms.asyncWriter
	// Release acknowledgements continuously; never retain one per file chunk.
	for len(w.pending) > 0 {
		select {
		case err := <-w.pending[0]:
			w.pending[0] = nil
			w.pending = w.pending[1:]
			if err != nil {
				return err
			}
		default:
			goto drained
		}
	}
drained:
	if kind == MsgDone {
		for _, done := range w.pending {
			select {
			case err := <-done:
				if err != nil {
					return err
				}
			case <-ctx.Done():
				return context.Cause(ctx)
			}
		}
		w.pending = nil
	}
	target := 0
	if kind == MsgData {
		if len(w.pending) >= int(CreditWindow) {
			select {
			case err := <-w.pending[0]:
				w.pending[0] = nil
				w.pending = w.pending[1:]
				if err != nil {
					return err
				}
			case <-ctx.Done():
				return context.Cause(ctx)
			}
		}
		seq := ms.globalSeq.Add(1) - 1
		target = int(seq % uint64(ms.n))
		if ms.balanced {
			load := func(i int) uint64 {
				queued := uint64(max(0, w.queuedBytes[i].Load()))
				if c, ok := ms.conns[i].(BufferedAmounter); ok {
					queued += c.BufferedAmount()
				}
				return queued
			}
			best := load(target)
			for offset := 1; offset < ms.n; offset++ {
				i := int((seq + uint64(offset)) % uint64(ms.n))
				if candidate := load(i); candidate < best {
					target, best = i, candidate
				}
			}
		}
		payload := make([]byte, globalSeqSize+len(data))
		binary.BigEndian.PutUint64(payload, seq)
		copy(payload[globalSeqSize:], data)
		data = payload // caller's pooled input can now be released
	} else {
		data = append([]byte(nil), data...)
	}
	job := &streamWrite{kind: kind, data: data, done: make(chan error, 1)}
	w.queuedBytes[target].Add(int64(len(data)))
	select {
	case w.queues[target] <- job:
	case <-ctx.Done():
		w.queuedBytes[target].Add(-int64(len(data)))
		return context.Cause(ctx)
	}
	if kind == MsgData {
		w.pending = append(w.pending, job.done)
		return nil
	}
	select {
	case err := <-job.done:
		return err
	case <-ctx.Done():
		return ms.finishCanceledWrite(ctx, job)
	}
}

func (ms *MultiStream) finishCanceledWrite(ctx context.Context, job *streamWrite) error {
	// Prefer a result already published alongside cancellation.
	select {
	case err := <-job.done:
		return err
	default:
	}

	// Exactly one side claims a queued control: either cancellation abandons it
	// here, or the worker owns an active physical write whose result must win.
	if job.state.CompareAndSwap(streamWriteQueued, streamWriteCanceled) {
		return context.Cause(ctx)
	}

	// Cancellation is terminal for a MultiStream. Close every transport to
	// bound the active write, then join its actual result. In particular, a
	// successful Complete write must survive peer EOF racing its return.
	_ = ms.Close()
	return <-job.done
}
