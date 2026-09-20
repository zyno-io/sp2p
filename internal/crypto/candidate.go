// SPDX-License-Identifier: MIT

package crypto

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"time"
)

// AuthenticateCandidate proves possession of the session key using fresh,
// connection-bound challenges. The sender chooses one authenticated transport;
// the receiver returns only after that authenticated selection arrives.
// No file-encryption nonce is consumed by this handshake.
func AuthenticateCandidate(ctx context.Context, rw io.ReadWriter, keys *DerivedKeys, senderPub, receiverPub []byte, sender bool) (func(context.Context) error, error) {
	ds, ok := rw.(DeadlineSetter)
	if !ok {
		return nil, fmt.Errorf("candidate has no deadline support")
	}
	fired := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { ds.SetDeadline(time.Now()); close(fired) })
	defer func() {
		if !stop() {
			<-fired
		}
		ds.SetDeadline(time.Time{})
	}()
	ds.SetDeadline(time.Now().Add(5 * time.Second))
	var mine, peer [32]byte
	if _, err := rand.Read(mine[:]); err != nil {
		return nil, err
	}
	exchange := func(out, in []byte) error {
		if sender {
			if _, err := writeAll(rw, out); err != nil {
				return err
			}
			_, err := io.ReadFull(rw, in)
			return err
		}
		if _, err := io.ReadFull(rw, in); err != nil {
			return err
		}
		_, err := writeAll(rw, out)
		return err
	}
	if err := exchange(mine[:], peer[:]); err != nil {
		return nil, fmt.Errorf("candidate challenge: %w", err)
	}
	sn, rn := mine[:], peer[:]
	if !sender {
		sn, rn = peer[:], mine[:]
	}
	proof := func(label string) []byte {
		mac := hmac.New(sha256.New, keys.Confirm)
		mac.Write([]byte("sp2p/v3/candidate/" + label))
		mac.Write(senderPub)
		mac.Write(receiverPub)
		mac.Write(sn)
		mac.Write(rn)
		return mac.Sum(nil)
	}
	role, other := "sender", "receiver"
	if !sender {
		role, other = other, role
	}
	var received [32]byte
	if err := exchange(proof(role), received[:]); err != nil {
		return nil, fmt.Errorf("candidate proof: %w", err)
	}
	if !hmac.Equal(received[:], proof(other)) {
		return nil, fmt.Errorf("candidate authentication failed")
	}
	if sender {
		return func(selectCtx context.Context) error {
			ds.SetDeadline(time.Now().Add(5 * time.Second))
			defer ds.SetDeadline(time.Time{})
			if err := selectCtx.Err(); err != nil {
				return err
			}
			if _, err := writeAll(rw, proof("select")); err != nil {
				return err
			}
			var ack [32]byte
			if _, err := io.ReadFull(rw, ack[:]); err != nil {
				return err
			}
			if !hmac.Equal(ack[:], proof("selected")) {
				return fmt.Errorf("candidate selection failed")
			}
			return nil
		}, nil
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}
	ds.SetDeadline(deadline)
	if _, err := io.ReadFull(rw, received[:]); err != nil {
		return nil, fmt.Errorf("awaiting candidate selection: %w", err)
	}
	if !hmac.Equal(received[:], proof("select")) {
		return nil, fmt.Errorf("invalid candidate selection")
	}
	if _, err := writeAll(rw, proof("selected")); err != nil {
		return nil, err
	}
	return nil, nil
}
