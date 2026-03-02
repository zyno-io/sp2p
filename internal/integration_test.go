// SPDX-License-Identifier: MIT

package internal

import (
	"bytes"
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zyno-io/sp2p/internal/crypto"
	"github.com/zyno-io/sp2p/internal/server"
	"github.com/zyno-io/sp2p/internal/signal"
	"github.com/zyno-io/sp2p/internal/transfer"
)

// TestSignalingRoundTrip tests the full signaling flow: sender registers,
// receiver joins, messages are relayed correctly.
func TestSignalingRoundTrip(t *testing.T) {
	// Start a signaling server using httptest.
	srv, err := server.New(server.Config{
		Addr:    ":0",
		BaseURL: "http://localhost",
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	srvHandler := httptest.NewServer(srv.Handler())
	defer srvHandler.Close()

	wsURL := "ws" + strings.TrimPrefix(srvHandler.URL, "http") + "/ws"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Sender connects and registers.
	sender, err := signal.Connect(ctx, wsURL)
	if err != nil {
		t.Fatalf("sender connect: %v", err)
	}
	defer sender.Close()

	if err := sender.Send(ctx, signal.TypeHello, signal.Hello{Version: signal.ProtocolVersion}); err != nil {
		t.Fatalf("send hello: %v", err)
	}

	// Wait for welcome.
	var sessionID string
	select {
	case env := <-sender.Incoming:
		if env.Type != signal.TypeWelcome {
			t.Fatalf("expected welcome, got %s", env.Type)
		}
		var welcome signal.Welcome
		env.ParsePayload(&welcome)
		sessionID = welcome.SessionID
	case <-ctx.Done():
		t.Fatal("timeout waiting for welcome")
	}

	if sessionID == "" {
		t.Fatal("empty session ID")
	}
	t.Logf("session ID: %s", sessionID)

	// Receiver connects and joins.
	receiver, err := signal.Connect(ctx, wsURL)
	if err != nil {
		t.Fatalf("receiver connect: %v", err)
	}
	defer receiver.Close()

	if err := receiver.Send(ctx, signal.TypeJoin, signal.Join{
		Version:   signal.ProtocolVersion,
		SessionID: sessionID,
	}); err != nil {
		t.Fatalf("send join: %v", err)
	}

	// Sender should get peer-joined.
	select {
	case env := <-sender.Incoming:
		if env.Type != signal.TypePeerJoined {
			t.Fatalf("expected peer-joined, got %s", env.Type)
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for peer-joined")
	}

	// Consume receiver welcome.
	select {
	case env := <-receiver.Incoming:
		if env.Type != signal.TypeWelcome {
			t.Fatalf("expected welcome, got %s", env.Type)
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for receiver welcome")
	}

	// Test message relay: sender sends crypto, receiver gets it.
	testPub := make([]byte, 32)
	for i := range testPub {
		testPub[i] = byte(i)
	}
	sender.Send(ctx, signal.TypeCrypto, signal.CryptoExchange{PublicKey: testPub})

	select {
	case env := <-receiver.Incoming:
		if env.Type != signal.TypeCrypto {
			t.Fatalf("expected crypto, got %s", env.Type)
		}
		var ce signal.CryptoExchange
		env.ParsePayload(&ce)
		if !bytes.Equal(ce.PublicKey, testPub) {
			t.Fatal("public key mismatch")
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for crypto relay")
	}

	t.Log("signaling round-trip passed")
}

// TestKeyDerivationSymmetry verifies that sender and receiver derive identical keys.
func TestKeyDerivationSymmetry(t *testing.T) {
	senderKP, _ := crypto.GenerateKeyPair()
	receiverKP, _ := crypto.GenerateKeyPair()
	_, seedRaw, _ := crypto.GenerateSeed()
	sessionID := "testsess"

	sKeys, err := crypto.DeriveKeys(senderKP.Private, receiverKP.Public, seedRaw, sessionID, senderKP.Public, receiverKP.Public)
	if err != nil {
		t.Fatal(err)
	}

	rKeys, err := crypto.DeriveKeys(receiverKP.Private, senderKP.Public, seedRaw, sessionID, senderKP.Public, receiverKP.Public)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(sKeys.SenderToReceiver, rKeys.SenderToReceiver) {
		t.Fatal("SenderToReceiver mismatch")
	}
	if !bytes.Equal(sKeys.ReceiverToSender, rKeys.ReceiverToSender) {
		t.Fatal("ReceiverToSender mismatch")
	}
	if sKeys.VerifyCode != rKeys.VerifyCode {
		t.Fatal("verify code mismatch")
	}
}

// TestEncryptedTransfer tests a full send/receive over encrypted pipes.
func TestEncryptedTransfer(t *testing.T) {
	senderKP, _ := crypto.GenerateKeyPair()
	receiverKP, _ := crypto.GenerateKeyPair()
	_, seedRaw, _ := crypto.GenerateSeed()
	sessionID := "testsess"

	sKeys, _ := crypto.DeriveKeys(senderKP.Private, receiverKP.Public, seedRaw, sessionID, senderKP.Public, receiverKP.Public)

	// Two pipes for bidirectional communication.
	sr, sw := io.Pipe() // sender → receiver
	rr, rw := io.Pipe() // receiver → sender

	senderStream, err := crypto.NewEncryptedStream(
		&duplexRW{r: rr, w: sw},
		sKeys.SenderToReceiver,
		sKeys.ReceiverToSender,
	)
	if err != nil {
		t.Fatal(err)
	}

	receiverStream, err := crypto.NewEncryptedStream(
		&duplexRW{r: sr, w: rw},
		sKeys.ReceiverToSender,
		sKeys.SenderToReceiver,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Create test data.
	fileData := bytes.Repeat([]byte("hello sp2p "), 5000) // ~55KB
	meta := &transfer.Metadata{
		Name: "test.bin",
		Size: uint64(len(fileData)),
		Type: "application/octet-stream",
	}

	errCh := make(chan error, 2)
	var receivedMeta *transfer.Metadata
	var receivedData bytes.Buffer

	// Receiver goroutine.
	go func() {
		recv := transfer.NewReceiver(receiverStream)
		var err error
		receivedMeta, err = recv.Receive(context.Background(), &receivedData, nil)
		errCh <- err
	}()

	// Sender.
	go func() {
		sender := transfer.NewSender(senderStream, meta)
		errCh <- sender.Send(context.Background(), bytes.NewReader(fileData), nil)
	}()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("transfer error: %v", err)
		}
	}

	if receivedMeta.Name != "test.bin" {
		t.Fatalf("name mismatch: %s", receivedMeta.Name)
	}
	if !bytes.Equal(receivedData.Bytes(), fileData) {
		t.Fatalf("data mismatch: got %d bytes, want %d", receivedData.Len(), len(fileData))
	}

	t.Logf("encrypted transfer passed: %d bytes", len(fileData))
}

// TestSeedRoundTrip tests seed encode/decode.
func TestSeedRoundTrip(t *testing.T) {
	for i := 0; i < 100; i++ {
		encoded, raw, err := crypto.GenerateSeed()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := crypto.DecodeSeed(encoded)
		if err != nil {
			t.Fatalf("decode error for %q: %v", encoded, err)
		}
		if !bytes.Equal(raw, decoded) {
			t.Fatalf("round-trip %d failed: %x != %x (encoded: %s)", i, raw, decoded, encoded)
		}
	}
}

// TestCodeFormat tests code formatting and parsing.
func TestCodeFormat(t *testing.T) {
	tests := []struct {
		session, seed string
	}{
		{"abc12345", "RF6k7wc5do8cAMuAHaaEEFJy"},
		{"xxyyzzww", "A"},
		{"a", "b"},
	}
	for _, tt := range tests {
		code := crypto.FormatCode(tt.session, tt.seed)
		s, e, err := crypto.ParseCode(code)
		if err != nil {
			t.Fatalf("ParseCode(%q): %v", code, err)
		}
		if s != tt.session || e != tt.seed {
			t.Fatalf("ParseCode(%q): got (%q, %q), want (%q, %q)", code, s, e, tt.session, tt.seed)
		}
	}

	// Invalid codes.
	for _, bad := range []string{"", "noseparator", "-nosession", "noseed-"} {
		_, _, err := crypto.ParseCode(bad)
		if err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}

type duplexRW struct {
	r io.Reader
	w io.Writer
}

func (d *duplexRW) Read(p []byte) (int, error)  { return d.r.Read(p) }
func (d *duplexRW) Write(p []byte) (int, error) { return d.w.Write(p) }

// pipeConn wraps two io.Pipe pairs to form a closable, deadline-capable connection.
// Closing the conn unblocks any pending Read/Write by closing the underlying pipes.
type pipeConn struct {
	r      *io.PipeReader
	w      *io.PipeWriter
	mu     sync.Mutex
	timer  *time.Timer
	closed bool
}

func (pc *pipeConn) Read(p []byte) (int, error)  { return pc.r.Read(p) }
func (pc *pipeConn) Write(p []byte) (int, error) { return pc.w.Write(p) }

func (pc *pipeConn) Close() error {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if pc.closed {
		return nil
	}
	pc.closed = true
	if pc.timer != nil {
		pc.timer.Stop()
	}
	pc.r.CloseWithError(io.ErrClosedPipe)
	pc.w.CloseWithError(io.ErrClosedPipe)
	return nil
}

func (pc *pipeConn) SetDeadline(t time.Time) error {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if pc.timer != nil {
		pc.timer.Stop()
		pc.timer = nil
	}
	if t.IsZero() {
		return nil
	}
	d := time.Until(t)
	if d <= 0 {
		pc.r.CloseWithError(io.ErrClosedPipe)
		pc.w.CloseWithError(io.ErrClosedPipe)
		return nil
	}
	pc.timer = time.AfterFunc(d, func() { pc.Close() })
	return nil
}

// newPipeConnPair creates two connected pipeConns. Data written to a appears
// as reads on b, and vice versa.
//
// Each direction uses two io.Pipe pairs with a goroutine in between. This
// provides decoupling so both sides can write before reading (io.Pipe is
// unbuffered, which would deadlock without this — e.g. key confirmation
// where both sides write 32 bytes before reading the peer's 32 bytes).
func newPipeConnPair() (*pipeConn, *pipeConn) {
	// a→b direction: a writes to aWW, goroutine copies to bRW, b reads from bRR.
	aWR, aWW := io.Pipe()
	bRR, bRW := io.Pipe()
	go func() {
		io.Copy(bRW, aWR)
		bRW.Close() // signal EOF to b's reader
		aWR.Close() // signal broken pipe to a's writer
	}()

	// b→a direction: b writes to bWW, goroutine copies to aRW, a reads from aRR.
	bWR, bWW := io.Pipe()
	aRR, aRW := io.Pipe()
	go func() {
		io.Copy(aRW, bWR)
		aRW.Close() // signal EOF to a's reader
		bWR.Close() // signal broken pipe to b's writer
	}()

	return &pipeConn{r: aRR, w: aWW}, &pipeConn{r: bRR, w: bWW}
}

// fullFlowSetup orchestrates the full signaling → key exchange → key confirmation
// → encrypted stream setup in a single process. Returns two FrameReadWriters
// (sender, receiver) and the underlying pipeConns for deadline control.
func fullFlowSetup(t *testing.T) (senderFRW, receiverFRW transfer.FrameReadWriter, sConn, rConn *pipeConn) {
	t.Helper()

	srv, err := server.New(server.Config{Addr: ":0", BaseURL: "http://localhost"})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	// 1. Sender connects and registers.
	senderSig, err := signal.Connect(ctx, wsURL)
	if err != nil {
		t.Fatalf("sender connect: %v", err)
	}
	t.Cleanup(func() { senderSig.Close() })

	if err := senderSig.Send(ctx, signal.TypeHello, signal.Hello{Version: signal.ProtocolVersion}); err != nil {
		t.Fatalf("send hello: %v", err)
	}

	// 2. Wait for welcome with session ID.
	var sessionID string
	select {
	case env := <-senderSig.Incoming:
		if env.Type != signal.TypeWelcome {
			t.Fatalf("expected welcome, got %s", env.Type)
		}
		var w signal.Welcome
		env.ParsePayload(&w)
		sessionID = w.SessionID
	case <-ctx.Done():
		t.Fatal("timeout waiting for welcome")
	}

	// 3. Receiver connects and joins.
	receiverSig, err := signal.Connect(ctx, wsURL)
	if err != nil {
		t.Fatalf("receiver connect: %v", err)
	}
	t.Cleanup(func() { receiverSig.Close() })

	if err := receiverSig.Send(ctx, signal.TypeJoin, signal.Join{
		Version: signal.ProtocolVersion, SessionID: sessionID,
	}); err != nil {
		t.Fatalf("send join: %v", err)
	}

	// 4. Sender gets peer-joined.
	select {
	case env := <-senderSig.Incoming:
		if env.Type != signal.TypePeerJoined {
			t.Fatalf("expected peer-joined, got %s", env.Type)
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for peer-joined")
	}
	// Consume receiver welcome.
	select {
	case env := <-receiverSig.Incoming:
		if env.Type != signal.TypeWelcome {
			t.Fatalf("expected receiver welcome, got %s", env.Type)
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for receiver welcome")
	}

	// 5. Generate key pairs and exchange public keys.
	senderKP, _ := crypto.GenerateKeyPair()
	receiverKP, _ := crypto.GenerateKeyPair()

	senderSig.Send(ctx, signal.TypeCrypto, signal.CryptoExchange{PublicKey: senderKP.Public})
	receiverSig.Send(ctx, signal.TypeCrypto, signal.CryptoExchange{PublicKey: receiverKP.Public})

	// Receiver reads sender's pubkey.
	select {
	case env := <-receiverSig.Incoming:
		if env.Type != signal.TypeCrypto {
			t.Fatalf("expected crypto, got %s", env.Type)
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for receiver crypto")
	}
	// Sender reads receiver's pubkey.
	select {
	case env := <-senderSig.Incoming:
		if env.Type != signal.TypeCrypto {
			t.Fatalf("expected crypto, got %s", env.Type)
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for sender crypto")
	}

	// 6. Generate seed and derive keys.
	_, seedRaw, err := crypto.GenerateSeed()
	if err != nil {
		t.Fatal(err)
	}
	sKeys, err := crypto.DeriveKeys(senderKP.Private, receiverKP.Public, seedRaw, sessionID, senderKP.Public, receiverKP.Public)
	if err != nil {
		t.Fatal(err)
	}
	rKeys, err := crypto.DeriveKeys(receiverKP.Private, senderKP.Public, seedRaw, sessionID, senderKP.Public, receiverKP.Public)
	if err != nil {
		t.Fatal(err)
	}

	// 7. Create pipeConn pair for the "P2P connection".
	sConn, rConn = newPipeConnPair()
	t.Cleanup(func() { sConn.Close(); rConn.Close() })

	// 8. Run key confirmation concurrently.
	confirmErrs := make(chan error, 2)
	go func() {
		confirmErrs <- crypto.SendConfirmation(ctx, sConn, sKeys, senderKP.Public, receiverKP.Public, true)
	}()
	go func() {
		confirmErrs <- crypto.SendConfirmation(ctx, rConn, rKeys, senderKP.Public, receiverKP.Public, false)
	}()
	for i := 0; i < 2; i++ {
		if err := <-confirmErrs; err != nil {
			t.Fatalf("key confirmation: %v", err)
		}
	}

	// 9. Wrap in encrypted streams.
	sStream, err := crypto.NewEncryptedStream(sConn, sKeys.SenderToReceiver, sKeys.ReceiverToSender)
	if err != nil {
		t.Fatal(err)
	}
	rStream, err := crypto.NewEncryptedStream(rConn, rKeys.ReceiverToSender, rKeys.SenderToReceiver)
	if err != nil {
		t.Fatal(err)
	}

	return sStream, rStream, sConn, rConn
}

// TestFullFlowTransfer tests the complete pipeline: signaling → key exchange →
// key confirmation → encrypted transfer in a single process.
func TestFullFlowTransfer(t *testing.T) {
	senderFRW, receiverFRW, _, _ := fullFlowSetup(t)

	fileData := bytes.Repeat([]byte("hello sp2p "), 5000) // ~55KB
	meta := &transfer.Metadata{
		Name: "fullflow.bin",
		Size: uint64(len(fileData)),
		Type: "application/octet-stream",
	}

	errCh := make(chan error, 2)
	var receivedMeta *transfer.Metadata
	var receivedData bytes.Buffer

	go func() {
		recv := transfer.NewReceiver(receiverFRW)
		var err error
		receivedMeta, err = recv.Receive(context.Background(), &receivedData, nil)
		errCh <- err
	}()
	go func() {
		s := transfer.NewSender(senderFRW, meta)
		errCh <- s.Send(context.Background(), bytes.NewReader(fileData), nil)
	}()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("transfer error: %v", err)
		}
	}

	if receivedMeta.Name != "fullflow.bin" {
		t.Fatalf("name mismatch: got %q", receivedMeta.Name)
	}
	if !bytes.Equal(receivedData.Bytes(), fileData) {
		t.Fatalf("data mismatch: got %d bytes, want %d", receivedData.Len(), len(fileData))
	}
	t.Logf("full flow transfer passed: %d bytes", len(fileData))
}

// TestStreamModeTransfer tests transfer with StreamMode=true and Size=0 (unknown size).
func TestStreamModeTransfer(t *testing.T) {
	senderKP, _ := crypto.GenerateKeyPair()
	receiverKP, _ := crypto.GenerateKeyPair()
	_, seedRaw, _ := crypto.GenerateSeed()

	sKeys, _ := crypto.DeriveKeys(senderKP.Private, receiverKP.Public, seedRaw, "streamsess", senderKP.Public, receiverKP.Public)

	sr, sw := io.Pipe()
	rr, rw := io.Pipe()

	sStream, err := crypto.NewEncryptedStream(&duplexRW{r: rr, w: sw}, sKeys.SenderToReceiver, sKeys.ReceiverToSender)
	if err != nil {
		t.Fatal(err)
	}
	rStream, err := crypto.NewEncryptedStream(&duplexRW{r: sr, w: rw}, sKeys.ReceiverToSender, sKeys.SenderToReceiver)
	if err != nil {
		t.Fatal(err)
	}

	fileData := bytes.Repeat([]byte("stream data "), 1000) // ~12KB
	meta := &transfer.Metadata{
		Name:       "stream.txt",
		Size:       0, // unknown
		StreamMode: true,
	}

	errCh := make(chan error, 2)
	var receivedMeta *transfer.Metadata
	var receivedData bytes.Buffer

	go func() {
		recv := transfer.NewReceiver(rStream)
		var err error
		receivedMeta, err = recv.Receive(context.Background(), &receivedData, nil)
		errCh <- err
	}()
	go func() {
		s := transfer.NewSender(sStream, meta)
		errCh <- s.Send(context.Background(), bytes.NewReader(fileData), nil)
	}()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("transfer error: %v", err)
		}
	}

	if !receivedMeta.StreamMode {
		t.Fatal("expected StreamMode=true in received metadata")
	}
	if receivedMeta.Size != 0 {
		t.Fatalf("expected Size=0, got %d", receivedMeta.Size)
	}
	if !bytes.Equal(receivedData.Bytes(), fileData) {
		t.Fatalf("data mismatch: got %d bytes, want %d", receivedData.Len(), len(fileData))
	}
	t.Logf("stream mode transfer passed: %d bytes", len(fileData))
}

// TestKeyConfirmationWrongSeed verifies that key confirmation fails when
// the two peers derive keys from different seeds.
func TestKeyConfirmationWrongSeed(t *testing.T) {
	senderKP, _ := crypto.GenerateKeyPair()
	receiverKP, _ := crypto.GenerateKeyPair()
	_, seedRawA, _ := crypto.GenerateSeed()
	_, seedRawB, _ := crypto.GenerateSeed()

	sKeys, _ := crypto.DeriveKeys(senderKP.Private, receiverKP.Public, seedRawA, "badseed", senderKP.Public, receiverKP.Public)
	rKeys, _ := crypto.DeriveKeys(receiverKP.Private, senderKP.Public, seedRawB, "badseed", senderKP.Public, receiverKP.Public)

	sConn, rConn := newPipeConnPair()
	defer sConn.Close()
	defer rConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 2)
	go func() {
		errCh <- crypto.SendConfirmation(ctx, sConn, sKeys, senderKP.Public, receiverKP.Public, true)
	}()
	go func() {
		errCh <- crypto.SendConfirmation(ctx, rConn, rKeys, senderKP.Public, receiverKP.Public, false)
	}()

	var gotFailure bool
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			if strings.Contains(err.Error(), "key confirmation failed") {
				gotFailure = true
			} else {
				// The other side may get a pipe error when the failing side closes.
				t.Logf("side %d error (expected): %v", i, err)
			}
		}
	}
	if !gotFailure {
		t.Fatal("expected key confirmation failure with wrong seed")
	}
	t.Log("key confirmation correctly failed with wrong seed")
}

// TestTransferContextCancel verifies that cancelling the context during a
// transfer causes both sender and receiver to return promptly.
func TestTransferContextCancel(t *testing.T) {
	sConn, rConn := newPipeConnPair()
	defer sConn.Close()
	defer rConn.Close()

	senderKP, _ := crypto.GenerateKeyPair()
	receiverKP, _ := crypto.GenerateKeyPair()
	_, seedRaw, _ := crypto.GenerateSeed()
	sKeys, _ := crypto.DeriveKeys(senderKP.Private, receiverKP.Public, seedRaw, "cancelsess", senderKP.Public, receiverKP.Public)

	sStream, _ := crypto.NewEncryptedStream(sConn, sKeys.SenderToReceiver, sKeys.ReceiverToSender)
	rStream, _ := crypto.NewEncryptedStream(rConn, sKeys.ReceiverToSender, sKeys.SenderToReceiver)

	// Use a large reader that will take a long time to transfer.
	largeReader := io.LimitReader(&zeroReader{}, 100*1024*1024) // 100 MB of zeros
	meta := &transfer.Metadata{Name: "big.dat", Size: 100 * 1024 * 1024}

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 2)

	go func() {
		recv := transfer.NewReceiver(rStream)
		recv.SetIdleTimeout(rConn, 30*time.Second)
		_, err := recv.Receive(ctx, io.Discard, nil)
		errCh <- err
	}()
	go func() {
		s := transfer.NewSender(sStream, meta)
		s.SetIdleTimeout(sConn, 30*time.Second)
		errCh <- s.Send(ctx, largeReader, nil)
	}()

	// Let some data flow, then cancel.
	time.Sleep(100 * time.Millisecond)
	cancel()

	timeout := time.After(5 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			if err == nil {
				t.Fatal("expected error after context cancel, got nil")
			}
			t.Logf("side %d returned: %v", i, err)
		case <-timeout:
			t.Fatal("transfer did not return within 5s after context cancel")
		}
	}
}

// TestConnectionDropMidTransfer verifies that closing the receiver's pipe
// mid-transfer causes both sides to get errors (not hang).
func TestConnectionDropMidTransfer(t *testing.T) {
	sConn, rConn := newPipeConnPair()
	defer sConn.Close()
	defer rConn.Close()

	senderKP, _ := crypto.GenerateKeyPair()
	receiverKP, _ := crypto.GenerateKeyPair()
	_, seedRaw, _ := crypto.GenerateSeed()
	sKeys, _ := crypto.DeriveKeys(senderKP.Private, receiverKP.Public, seedRaw, "dropsess", senderKP.Public, receiverKP.Public)

	sStream, _ := crypto.NewEncryptedStream(sConn, sKeys.SenderToReceiver, sKeys.ReceiverToSender)
	rStream, _ := crypto.NewEncryptedStream(rConn, sKeys.ReceiverToSender, sKeys.SenderToReceiver)

	largeReader := io.LimitReader(&zeroReader{}, 100*1024*1024)
	meta := &transfer.Metadata{Name: "drop.dat", Size: 100 * 1024 * 1024}

	errCh := make(chan error, 2)

	go func() {
		recv := transfer.NewReceiver(rStream)
		_, err := recv.Receive(context.Background(), io.Discard, nil)
		errCh <- err
	}()
	go func() {
		s := transfer.NewSender(sStream, meta)
		errCh <- s.Send(context.Background(), largeReader, nil)
	}()

	// Let some data flow, then close the receiver's connection.
	time.Sleep(100 * time.Millisecond)
	rConn.Close()

	timeout := time.After(5 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			if err == nil {
				t.Fatal("expected error after connection drop, got nil")
			}
			t.Logf("side %d returned: %v", i, err)
		case <-timeout:
			t.Fatal("transfer did not return within 5s after connection drop")
		}
	}
}

// TestOnMetadataCallback verifies that the Receiver.OnMetadata callback fires
// before data arrives and contains the correct metadata fields.
func TestOnMetadataCallback(t *testing.T) {
	senderKP, _ := crypto.GenerateKeyPair()
	receiverKP, _ := crypto.GenerateKeyPair()
	_, seedRaw, _ := crypto.GenerateSeed()
	sKeys, _ := crypto.DeriveKeys(senderKP.Private, receiverKP.Public, seedRaw, "metasess", senderKP.Public, receiverKP.Public)

	sr, sw := io.Pipe()
	rr, rw := io.Pipe()

	sStream, _ := crypto.NewEncryptedStream(&duplexRW{r: rr, w: sw}, sKeys.SenderToReceiver, sKeys.ReceiverToSender)
	rStream, _ := crypto.NewEncryptedStream(&duplexRW{r: sr, w: rw}, sKeys.ReceiverToSender, sKeys.SenderToReceiver)

	fileData := []byte("callback test data")
	meta := &transfer.Metadata{
		Name:      "project",
		Size:      uint64(len(fileData)),
		IsFolder:  true,
		FileCount: 5,
	}

	errCh := make(chan error, 2)
	var callbackMeta *transfer.Metadata
	callbackFired := make(chan struct{})

	go func() {
		recv := transfer.NewReceiver(rStream)
		recv.OnMetadata = func(m *transfer.Metadata) {
			callbackMeta = m
			close(callbackFired)
		}
		_, err := recv.Receive(context.Background(), io.Discard, nil)
		errCh <- err
	}()
	go func() {
		s := transfer.NewSender(sStream, meta)
		errCh <- s.Send(context.Background(), bytes.NewReader(fileData), nil)
	}()

	// Verify callback fires.
	select {
	case <-callbackFired:
	case <-time.After(5 * time.Second):
		t.Fatal("OnMetadata callback did not fire within 5s")
	}

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("transfer error: %v", err)
		}
	}

	if callbackMeta == nil {
		t.Fatal("OnMetadata was not called")
	}
	if callbackMeta.FileCount != 5 {
		t.Fatalf("expected FileCount=5, got %d", callbackMeta.FileCount)
	}
	if !callbackMeta.IsFolder {
		t.Fatal("expected IsFolder=true")
	}
	if callbackMeta.Name != "project" {
		t.Fatalf("expected Name=%q, got %q", "project", callbackMeta.Name)
	}
	t.Log("OnMetadata callback passed")
}

// zeroReader is an io.Reader that returns zero bytes forever.
type zeroReader struct{}

func (z *zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
