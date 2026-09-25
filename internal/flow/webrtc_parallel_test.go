// SPDX-License-Identifier: MIT

package flow

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestWebRTCSetupControlBoundsAndOrdering(t *testing.T) {
	for _, tc := range []struct {
		name  string
		kind  byte
		data  string
		valid bool
	}{
		{"valid", webRTCParallelMessage, `{"step":"ready","mask":14}`, true},
		{"wrong type", 2, `{"step":"ready"}`, false},
		{"wrong step", webRTCParallelMessage, `{"step":"commit"}`, false},
		{"malformed", webRTCParallelMessage, `{`, false},
		{"null", webRTCParallelMessage, `null`, false},
		{"negative mask", webRTCParallelMessage, `{"step":"ready","mask":-1}`, false},
		{"overflow mask", webRTCParallelMessage, `{"step":"ready","mask":4294967296}`, false},
		{"fractional mask", webRTCParallelMessage, `{"step":"ready","mask":2.5}`, false},
		{"oversize", webRTCParallelMessage, `{"step":"ready","extra":"` + strings.Repeat("x", 16*1024) + `"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseWebRTCParallelControl(tc.kind, []byte(tc.data), "ready")
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}

func nonce32() []byte { return bytes.Repeat([]byte{1}, 32) }

// v050ParallelControl mirrors the released v0.5.0 hello decoding, which has
// no Max field, together with its hello validation.
type v050ParallelControl struct {
	Step    string `json:"step"`
	Version int    `json:"version,omitempty"`
	Count   int    `json:"count,omitempty"`
	Nonce   []byte `json:"nonce,omitempty"`
}

func v050AcceptHello(t *testing.T, data []byte) int {
	t.Helper()
	var hello v050ParallelControl
	if err := json.Unmarshal(data, &hello); err != nil || hello.Step != "hello" {
		t.Fatalf("v0.5.0 receiver could not decode hello: %v", err)
	}
	if hello.Version != 1 || hello.Count < 1 || hello.Count > 4 || len(hello.Nonce) != 32 {
		t.Fatalf("v0.5.0 receiver rejects hello %s", data)
	}
	return min(4, hello.Count)
}

// newAcceptHello decodes a hello exactly as negotiateWebRTC does.
func newAcceptHello(t *testing.T, data []byte, limit int) int {
	t.Helper()
	hello, err := parseWebRTCParallelControl(webRTCParallelMessage, data, "hello")
	if err != nil {
		t.Fatal(err)
	}
	count, err := acceptWebRTCParallelHello(hello, limit)
	if err != nil {
		t.Fatalf("new receiver rejected hello %s: %v", data, err)
	}
	return count
}

func TestWebRTCParallelHelloCompatibility(t *testing.T) {
	marshal := func(value any) []byte {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	for _, requested := range []int{1, 2, 4, 5, 8} {
		data := marshal(webRTCParallelHello(requested, nonce32()))
		if got, want := newAcceptHello(t, data, webRTCParallelLimit), requested; got != want {
			t.Errorf("new sender %d -> new receiver accepted %d, want %d", requested, got, want)
		}
		if got, want := newAcceptHello(t, data, 5), min(5, requested); got != want {
			t.Errorf("new sender %d -> new receiver limited to 5 accepted %d, want %d", requested, got, want)
		}
		if got, want := v050AcceptHello(t, data), min(4, requested); got != want {
			t.Errorf("new sender %d -> v0.5.0 receiver accepted %d, want %d", requested, got, want)
		}
	}
	for _, requested := range []int{1, 4} {
		legacy := marshal(v050ParallelControl{Step: "hello", Version: 1, Count: requested, Nonce: nonce32()})
		if got := newAcceptHello(t, legacy, webRTCParallelLimit); got != requested {
			t.Errorf("v0.5.0 sender %d -> new receiver accepted %d", requested, got)
		}
	}
}

// TestWebRTCParallelHelloRejectsInvalidMax covers the Max validity rules: it
// must be 5..8, and only ever alongside count == the legacy limit.
func TestWebRTCParallelHelloRejectsInvalidMax(t *testing.T) {
	for _, tc := range []struct {
		name  string
		hello webRTCParallelControl
	}{
		{"max above limit", webRTCParallelControl{Step: "hello", Version: 1, Count: 4, Max: 9, Nonce: nonce32()}},
		{"max at or below legacy limit", webRTCParallelControl{Step: "hello", Version: 1, Count: 4, Max: 3, Nonce: nonce32()}},
		{"max with mismatched count", webRTCParallelControl{Step: "hello", Version: 1, Count: 3, Max: 8, Nonce: nonce32()}},
		{"max equal to legacy limit", webRTCParallelControl{Step: "hello", Version: 1, Count: 4, Max: 4, Nonce: nonce32()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := resolveHelloRequest(tc.hello); err == nil {
				t.Fatalf("accepted invalid hello %+v", tc.hello)
			}
		})
	}
}
