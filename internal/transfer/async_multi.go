// SPDX-License-Identifier: MIT

package transfer

import (
	"context"
	"encoding/binary"
)

type streamWrite struct {
	kind byte
	data []byte
	done chan error
}
type asyncMultiWriter struct {
	queues  []chan streamWrite
	pending []chan error
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
		w := &asyncMultiWriter{queues: make([]chan streamWrite, ms.n)}
		for i := range w.queues {
			q := make(chan streamWrite, CreditWindow)
			w.queues[i] = q
			go func(index int) {
				for {
					select {
					case <-ctx.Done():
						return
					case job := <-q:
						err := write(ms.streams[index], job.kind, job.data)
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
		payload := make([]byte, globalSeqSize+len(data))
		binary.BigEndian.PutUint64(payload, seq)
		copy(payload[globalSeqSize:], data)
		data = payload // caller's pooled input can now be released
	} else {
		data = append([]byte(nil), data...)
	}
	job := streamWrite{kind, data, make(chan error, 1)}
	select {
	case w.queues[target] <- job:
	case <-ctx.Done():
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
		return context.Cause(ctx)
	}
}
