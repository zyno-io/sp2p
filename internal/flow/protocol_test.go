// SPDX-License-Identifier: MIT

package flow

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/zyno-io/sp2p/internal/signal"
	"github.com/zyno-io/sp2p/internal/transfer"
)

type protocolHandler struct {
	relayPromptTestHandler
	warnings []string
	protocol int
}

func (h *protocolHandler) OnWarning(message string)      { h.warnings = append(h.warnings, message) }
func (h *protocolHandler) OnProtocolVersion(version int) { h.protocol = version }

func TestReportNegotiatedProtocol(t *testing.T) {
	for _, version := range []int{2, 3} {
		h := &protocolHandler{}
		reportProtocol(version, h)
		if h.protocol != version {
			t.Fatal("did not report selected protocol")
		}
		if (len(h.warnings) != 0) != (version == 2) {
			t.Fatalf("warnings: %+v", h.warnings)
		}
	}
}

func TestProtocolMismatchNeverRetriesOrDowngrades(t *testing.T) {
	for _, receive := range []bool{false, true} {
		var calls atomic.Int32
		versions := make(chan int, 4)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			c, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer c.CloseNow()
			_, data, err := c.Read(r.Context())
			if err != nil {
				return
			}
			var env signal.Envelope
			if err := json.Unmarshal(data, &env); err != nil {
				t.Error(err)
				return
			}
			var hello signal.Hello
			if err := env.ParsePayload(&hello); err != nil {
				t.Error(err)
				return
			}
			versions <- hello.Version
			response, _ := signal.NewEnvelope(signal.TypeError, signal.Error{Code: signal.ErrCodeVersionMismatch, Message: "unsupported protocol version"})
			encoded, _ := json.Marshal(response)
			if err := c.Write(r.Context(), websocket.MessageText, encoded); err != nil {
				return
			}
			for {
				if _, _, err := c.Read(r.Context()); err != nil {
					return
				}
			}
		}))
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		h := &protocolHandler{relayPromptTestHandler: relayPromptTestHandler{errors: make(chan string, 4)}}
		url := "ws" + strings.TrimPrefix(srv.URL, "http")
		var err error
		if receive {
			_, err = Receive(ctx, ReceiveConfig{ServerURL: url, Code: "abcdefgh-1"}, h)
		} else {
			err = Send(ctx, SendConfig{ServerURL: url, Meta: &transfer.Metadata{Name: "test"}}, h)
		}
		cancel()
		srv.Close()
		if err == nil {
			t.Fatal("expected protocol mismatch")
		}
		if calls.Load() != 1 {
			t.Fatalf("dial count: %d", calls.Load())
		}
		select {
		case version := <-versions:
			if version != 2 {
				t.Fatalf("advertised version: %d", version)
			}
		default:
			t.Fatal("no registration received")
		}
		if len(h.warnings) != 0 {
			t.Fatal("unexpected legacy mode")
		}
		if h.protocol != 0 {
			t.Fatal("reported protocol before authentication")
		}
	}
}
