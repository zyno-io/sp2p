// SPDX-License-Identifier: MIT

package crypto

import (
	"context"
	"fmt"
	"io"
	"time"
)

// ConfirmationSize is the size of the HMAC confirmation (SHA-256 output).
const ConfirmationSize = 32

// DeadlineSetter is implemented by connections that support deadlines.
type DeadlineSetter interface {
	SetDeadline(t time.Time) error
}

// SendConfirmation sends our key confirmation and reads/verifies the peer's.
// isSender determines which role labels are used.
// The context is used for cancellation — when ctx is cancelled, the underlying
// connection deadline is set to the past to unblock any pending I/O.
func SendConfirmation(ctx context.Context, rw io.ReadWriter, keys *DerivedKeys, senderPub, receiverPub []byte, isSender bool) error {
	// If the connection supports deadlines, watch for context cancellation.
	if ds, ok := rw.(DeadlineSetter); ok {
		done := make(chan struct{})
		defer close(done)
		go func() {
			select {
			case <-ctx.Done():
				ds.SetDeadline(time.Now())
			case <-done:
			}
		}()
	}

	myRole := "sender"
	peerRole := "receiver"
	if !isSender {
		myRole = "receiver"
		peerRole = "sender"
	}

	// Compute and send our confirmation.
	myConfirm := ComputeConfirmation(keys.Confirm, myRole, senderPub, receiverPub)
	if _, err := writeAll(rw, myConfirm); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("sending key confirmation: %w", err)
	}

	// Read peer's confirmation.
	peerConfirm := make([]byte, ConfirmationSize)
	if _, err := io.ReadFull(rw, peerConfirm); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("reading key confirmation: %w", err)
	}

	// Verify.
	if !VerifyConfirmation(keys.Confirm, peerRole, senderPub, receiverPub, peerConfirm) {
		return fmt.Errorf("key confirmation failed — encryption seed may be wrong or MITM detected")
	}

	return nil
}
