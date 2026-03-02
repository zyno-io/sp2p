// SPDX-License-Identifier: MIT

package signal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// wsServer creates an httptest server that accepts a single WebSocket
// connection and returns the server-side conn. The caller must close the
// returned conn and server.
func wsServer(t *testing.T) (*httptest.Server, func() *websocket.Conn) {
	t.Helper()
	connCh := make(chan *websocket.Conn, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Logf("wsServer accept: %v", err)
			return
		}
		connCh <- c
	}))
	return srv, func() *websocket.Conn {
		t.Helper()
		select {
		case c := <-connCh:
			return c
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for server-side WebSocket conn")
			return nil
		}
	}
}

func connectClient(t *testing.T, srvURL string) *Client {
	t.Helper()
	wsURL := strings.Replace(srvURL, "http://", "ws://", 1)
	c, err := Connect(context.Background(), wsURL)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	return c
}

// sendEnvelope writes a JSON envelope on the server-side conn.
func sendEnvelope(t *testing.T, srvConn *websocket.Conn, msgType string, payload any) {
	t.Helper()
	env, err := NewEnvelope(msgType, payload)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("Marshal envelope: %v", err)
	}
	if err := srvConn.Write(context.Background(), websocket.MessageText, data); err != nil {
		t.Fatalf("server write: %v", err)
	}
}

// ── Subscribe / Unsubscribe ────────────────────────────────────────────────

func TestSubscribe_FilteredDelivery(t *testing.T) {
	srv, getConn := wsServer(t)
	defer srv.Close()

	client := connectClient(t, srv.URL)
	defer client.Close()

	srvConn := getConn()
	defer srvConn.Close(websocket.StatusNormalClosure, "")

	offerCh := client.Subscribe(TypeOffer)
	defer client.Unsubscribe(TypeOffer, offerCh)

	// Send an offer and a candidate from the server.
	sendEnvelope(t, srvConn, TypeOffer, &SDP{SDP: "v=0\r\n", Type: "offer"})
	sendEnvelope(t, srvConn, TypeCandidate, &Candidate{Candidate: "candidate:1"})

	// Offer should arrive on the subscription channel.
	select {
	case env := <-offerCh:
		if env.Type != TypeOffer {
			t.Fatalf("expected offer, got %s", env.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for offer on subscription")
	}

	// Candidate should arrive on the Incoming channel (not subscribed).
	select {
	case env := <-client.Incoming:
		if env.Type != TypeCandidate {
			t.Fatalf("expected candidate, got %s", env.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for candidate on Incoming")
	}
}

func TestUnsubscribe_ResumesIncoming(t *testing.T) {
	srv, getConn := wsServer(t)
	defer srv.Close()

	client := connectClient(t, srv.URL)
	defer client.Close()

	srvConn := getConn()
	defer srvConn.Close(websocket.StatusNormalClosure, "")

	ch := client.Subscribe(TypeOffer)

	// Unsubscribe immediately.
	client.Unsubscribe(TypeOffer, ch)

	// Now offers should go to Incoming.
	sendEnvelope(t, srvConn, TypeOffer, &SDP{SDP: "v=0\r\n", Type: "offer"})

	select {
	case env := <-client.Incoming:
		if env.Type != TypeOffer {
			t.Fatalf("expected offer on Incoming, got %s", env.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for offer on Incoming after unsubscribe")
	}
}

// ── Done channel ───────────────────────────────────────────────────────────

func TestDone_ClosesOnServerDisconnect(t *testing.T) {
	srv, getConn := wsServer(t)
	defer srv.Close()

	client := connectClient(t, srv.URL)
	defer client.Close()

	srvConn := getConn()

	// Close the server-side connection to trigger read loop exit.
	srvConn.Close(websocket.StatusNormalClosure, "bye")

	select {
	case <-client.Done():
		// Success — done channel closed.
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Done()")
	}
}

// ── Send ───────────────────────────────────────────────────────────────────

func TestSend_DeliversToServer(t *testing.T) {
	srv, getConn := wsServer(t)
	defer srv.Close()

	client := connectClient(t, srv.URL)
	defer client.Close()

	srvConn := getConn()
	defer srvConn.Close(websocket.StatusNormalClosure, "")

	// Client sends a hello message.
	err := client.Send(context.Background(), TypeHello, &Hello{Version: 1, ClientType: "cli"})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	// Read it on the server side.
	_, data, err := srvConn.Read(context.Background())
	if err != nil {
		t.Fatalf("server Read: %v", err)
	}

	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if env.Type != TypeHello {
		t.Fatalf("expected hello, got %s", env.Type)
	}

	var hello Hello
	if err := env.ParsePayload(&hello); err != nil {
		t.Fatalf("ParsePayload: %v", err)
	}
	if hello.Version != 1 || hello.ClientType != "cli" {
		t.Fatalf("hello = %+v, want version=1 clientType=cli", hello)
	}
}

func TestSend_ConcurrentSafe(t *testing.T) {
	srv, getConn := wsServer(t)
	defer srv.Close()

	client := connectClient(t, srv.URL)
	defer client.Close()

	srvConn := getConn()
	defer srvConn.Close(websocket.StatusNormalClosure, "")

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)

	errCh := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			errCh <- client.Send(context.Background(), TypeHello, &Hello{Version: 1})
		}()
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent Send error: %v", err)
		}
	}

	// Drain all messages on the server side.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	count := 0
	for count < n {
		_, _, err := srvConn.Read(ctx)
		if err != nil {
			break
		}
		count++
	}
	if count != n {
		t.Fatalf("received %d messages, want %d", count, n)
	}
}

// ── Incoming channel ───────────────────────────────────────────────────────

func TestIncoming_ReceivesUnsubscribedMessages(t *testing.T) {
	srv, getConn := wsServer(t)
	defer srv.Close()

	client := connectClient(t, srv.URL)
	defer client.Close()

	srvConn := getConn()
	defer srvConn.Close(websocket.StatusNormalClosure, "")

	// No subscriptions — everything goes to Incoming.
	sendEnvelope(t, srvConn, TypeWelcome, &Welcome{SessionID: "abc123"})

	select {
	case env := <-client.Incoming:
		if env.Type != TypeWelcome {
			t.Fatalf("expected welcome, got %s", env.Type)
		}
		var w Welcome
		if err := env.ParsePayload(&w); err != nil {
			t.Fatalf("ParsePayload: %v", err)
		}
		if w.SessionID != "abc123" {
			t.Fatalf("sessionId = %q, want abc123", w.SessionID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Incoming message")
	}
}

// ── Envelope / Messages ────────────────────────────────────────────────────

func TestNewEnvelope_RoundTrip(t *testing.T) {
	hello := &Hello{Version: 1, ClientType: "cli"}
	env, err := NewEnvelope(TypeHello, hello)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	if env.Type != TypeHello {
		t.Fatalf("type = %s, want hello", env.Type)
	}

	var decoded Hello
	if err := env.ParsePayload(&decoded); err != nil {
		t.Fatalf("ParsePayload: %v", err)
	}
	if decoded.Version != 1 || decoded.ClientType != "cli" {
		t.Fatalf("decoded = %+v, want version=1 clientType=cli", decoded)
	}
}

func TestEnvelope_JSONMarshal(t *testing.T) {
	env, _ := NewEnvelope(TypeError, &Error{Code: ErrCodeSessionFull, Message: "session is full"})
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded Envelope
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded.Type != TypeError {
		t.Fatalf("type = %s, want error", decoded.Type)
	}

	var errMsg Error
	if err := decoded.ParsePayload(&errMsg); err != nil {
		t.Fatalf("ParsePayload: %v", err)
	}
	if errMsg.Code != ErrCodeSessionFull {
		t.Fatalf("code = %s, want session_full", errMsg.Code)
	}
}
