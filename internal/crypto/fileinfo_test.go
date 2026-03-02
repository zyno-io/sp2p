// SPDX-License-Identifier: MIT

package crypto

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// FileInfo encryption tests
// ---------------------------------------------------------------------------

func TestFileInfoRoundTrip(t *testing.T) {
	seed := []byte("test-seed-value!")
	plaintext := []byte(`{"name":"hello.txt","size":42}`)

	encrypted, err := EncryptFileInfo(seed, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := DecryptFileInfo(seed, encrypted)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestFileInfoTamperedCiphertext(t *testing.T) {
	seed := []byte("test-seed-value!")
	plaintext := []byte("secret data")

	encrypted, err := EncryptFileInfo(seed, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Flip a byte in the ciphertext portion (after the 12-byte nonce).
	encrypted[len(encrypted)-1] ^= 0xff

	_, err = DecryptFileInfo(seed, encrypted)
	if err == nil {
		t.Fatal("expected decryption to fail with tampered ciphertext")
	}
}

func TestFileInfoShortCiphertext(t *testing.T) {
	seed := []byte("test-seed-value!")

	// NonceSize (12) + TagSize (16) = 28 is the minimum length.
	// Anything shorter must be rejected.
	short := make([]byte, NonceSize+TagSize-1)

	_, err := DecryptFileInfo(seed, short)
	if err == nil {
		t.Fatal("expected error for too-short ciphertext")
	}
}

func TestFileInfoWrongSeed(t *testing.T) {
	seed1 := []byte("correct-seed!!!!")
	seed2 := []byte("wrong-seed!!!!!!")
	plaintext := []byte("secret data")

	encrypted, err := EncryptFileInfo(seed1, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptFileInfo(seed2, encrypted)
	if err == nil {
		t.Fatal("expected decryption to fail with wrong seed")
	}
}

func TestFileInfoUniqueNonces(t *testing.T) {
	seed := []byte("test-seed-value!")
	plaintext := []byte("same plaintext")

	enc1, err := EncryptFileInfo(seed, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	enc2, err := EncryptFileInfo(seed, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(enc1, enc2) {
		t.Fatal("two encryptions of the same plaintext should differ (random nonce)")
	}
}

// ---------------------------------------------------------------------------
// SendConfirmation I/O tests
// ---------------------------------------------------------------------------

// tcpConnPair creates a pair of connected TCP connections via a loopback listener.
func tcpConnPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var serverConn net.Conn
	accepted := make(chan struct{})
	go func() {
		serverConn, err = ln.Accept()
		close(accepted)
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	<-accepted
	if serverConn == nil {
		t.Fatal("failed to accept connection")
	}

	return clientConn, serverConn
}

// deriveTestKeys generates two key pairs, a seed, and derives shared keys.
func deriveTestKeys(t *testing.T) (*DerivedKeys, []byte, []byte) {
	t.Helper()

	sender, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, seedRaw, err := GenerateSeed()
	if err != nil {
		t.Fatal(err)
	}

	keys, err := DeriveKeys(sender.Private, receiver.Public, seedRaw, "test-session", sender.Public, receiver.Public)
	if err != nil {
		t.Fatal(err)
	}

	return keys, sender.Public, receiver.Public
}

func TestSendConfirmation_Success(t *testing.T) {
	keys, senderPub, receiverPub := deriveTestKeys(t)

	connA, connB := tcpConnPair(t)
	defer connA.Close()
	defer connB.Close()

	ctx := context.Background()
	errs := make(chan error, 2)

	go func() {
		errs <- SendConfirmation(ctx, connA, keys, senderPub, receiverPub, true)
	}()
	go func() {
		errs <- SendConfirmation(ctx, connB, keys, senderPub, receiverPub, false)
	}()

	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("confirmation %d failed: %v", i, err)
		}
	}
}

func TestSendConfirmation_WrongKeys(t *testing.T) {
	keys1, senderPub1, receiverPub1 := deriveTestKeys(t)
	keys2, senderPub2, receiverPub2 := deriveTestKeys(t)

	connA, connB := tcpConnPair(t)
	defer connA.Close()
	defer connB.Close()

	ctx := context.Background()
	errs := make(chan error, 2)

	// Sender uses keys1, receiver uses keys2 -- confirmation must fail.
	go func() {
		errs <- SendConfirmation(ctx, connA, keys1, senderPub1, receiverPub1, true)
	}()
	go func() {
		errs <- SendConfirmation(ctx, connB, keys2, senderPub2, receiverPub2, false)
	}()

	failures := 0
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			failures++
		}
	}

	if failures == 0 {
		t.Fatal("expected at least one side to fail confirmation with mismatched keys")
	}
}

func TestSendConfirmation_ContextCancel(t *testing.T) {
	keys, senderPub, receiverPub := deriveTestKeys(t)

	// Use an io.Pipe where only one side is used -- the write will block
	// because nothing reads, then we cancel the context and close the pipe.
	r, w := io.Pipe()

	ctx, cancel := context.WithCancel(context.Background())

	errs := make(chan error, 1)
	go func() {
		errs <- SendConfirmation(ctx, &duplexPipe{r: r, w: w}, keys, senderPub, receiverPub, true)
	}()

	// Give the goroutine a moment to start, then cancel and unblock I/O.
	time.Sleep(50 * time.Millisecond)
	cancel()
	r.Close()
	w.Close()

	select {
	case err := <-errs:
		if err == nil {
			t.Fatal("expected an error after context cancellation")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for SendConfirmation to return")
	}
}
