// SPDX-License-Identifier: MIT

package flow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zyno-io/sp2p/internal/conn"
	"github.com/zyno-io/sp2p/internal/crypto"
	"github.com/zyno-io/sp2p/internal/transfer"
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

// TestClassifyLaneErrorBuckets checks the fixed five-value Class vocabulary.
// It intentionally embeds address-like text in some errors: classification
// is a substring match on err.Error() for a couple of buckets, but the
// bucket name — not the text — is all that ever leaves classifyLaneError.
func TestClassifyLaneErrorBuckets(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want LaneFailureClass
	}{
		{"deadline exceeded", fmt.Errorf("candidate proof near 203.0.113.9:51820: %w", context.DeadlineExceeded), ClassTimeout},
		{"context wrapped deadline", context.DeadlineExceeded, ClassTimeout},
		{"eof", fmt.Errorf("reading lane near 203.0.113.9:51821: %w", io.EOF), ClassEOF},
		{"unexpected eof", io.ErrUnexpectedEOF, ClassEOF},
		{"lane closed sentinel", conn.ErrLaneClosed, ClassClosed},
		{"net closed", net.ErrClosed, ClassClosed},
		{"closed text", fmt.Errorf("WebRTC lane closed during setup"), ClassClosed},
		{"authentication failed text", fmt.Errorf("candidate authentication failed"), ClassMismatch},
		{"commit mismatch text", fmt.Errorf("WebRTC commit mismatch"), ClassMismatch},
		{"generic error", fmt.Errorf("creating WebRTC lane: boom"), ClassError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyLaneError(tc.err); got != tc.want {
				t.Fatalf("classifyLaneError(%v) = %s, want %s", tc.err, got, tc.want)
			}
		})
	}
}

// TestReportParallelLanesGating checks reportParallelLanes' "any accepted
// extra lane was not selected" rule and that a Handler which doesn't
// implement ParallelLaneReporter is simply skipped.
func TestReportParallelLanesGating(t *testing.T) {
	t.Run("nil report is not reported", func(t *testing.T) {
		h := &laneReportTestHandler{}
		reportParallelLanes(h, nil)
		if h.report != nil {
			t.Fatal("expected no report call for a nil report")
		}
	})
	t.Run("every accepted extra lane selected is not reported", func(t *testing.T) {
		h := &laneReportTestHandler{}
		reportParallelLanes(h, &ParallelLaneReport{Accepted: 3, Selected: 0b110})
		if h.report != nil {
			t.Fatal("expected no report call when nothing was missed")
		}
	})
	t.Run("a missing accepted extra lane is reported", func(t *testing.T) {
		h := &laneReportTestHandler{}
		report := &ParallelLaneReport{Accepted: 3, Selected: 0b010}
		reportParallelLanes(h, report)
		if h.report != report {
			t.Fatal("expected the report to be forwarded")
		}
	})
	t.Run("handler without the optional interface is skipped", func(t *testing.T) {
		h := &relayRoleTestHandler{errs: make(chan string, 1)}
		reportParallelLanes(h, &ParallelLaneReport{Accepted: 3, Selected: 0}) // must not panic
	})
}

type laneReportTestHandler struct {
	relayRoleTestHandler
	report *ParallelLaneReport
}

func (h *laneReportTestHandler) OnParallelLaneReport(report *ParallelLaneReport) {
	h.report = report
}

var ipLikePattern = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)

func assertNoAddressLikeStrings(t *testing.T, s string) {
	t.Helper()
	if ipLikePattern.MatchString(s) {
		t.Fatalf("output contains an IP-like string: %s", s)
	}
	if strings.Contains(s, "203.0.113") {
		t.Fatalf("output leaked the synthetic test address: %s", s)
	}
}

// TestNegotiateWebRTCReportsCreateFailuresWithoutAddresses drives a real
// negotiateWebRTC call (receiver side) against a hand-rolled peer over an
// in-memory pipe, using the testLaneFault hook to force lane creation to
// fail for two lane ids without any real WebRTC connection. It checks the
// resulting report's shape (Requested/Accepted/Selected, one Failure per
// forced id, the right Stage/Class) and — the actual privacy requirement —
// that marshaling the report never leaks the address-like text embedded in
// the synthetic errors, matching how AuthenticateCandidate/Pion errors could
// look in production.
func TestNegotiateWebRTCReportsCreateFailuresWithoutAddresses(t *testing.T) {
	clientPipe, peerPipe := net.Pipe()
	defer clientPipe.Close()
	defer peerPipe.Close()

	keyA := bytes.Repeat([]byte{1}, 32)
	keyB := bytes.Repeat([]byte{2}, 32)
	clientStream, err := crypto.NewEncryptedStream(clientPipe, keyA, keyB)
	if err != nil {
		t.Fatal(err)
	}
	peerStream, err := crypto.NewEncryptedStream(peerPipe, keyB, keyA)
	if err != nil {
		t.Fatal(err)
	}

	testLaneFault = func(id int) error {
		if id == 1 {
			return fmt.Errorf("synthetic timeout near 203.0.113.9:51820: %w", context.DeadlineExceeded)
		}
		return fmt.Errorf("synthetic eof near 203.0.113.9:51821: %w", io.EOF)
	}
	defer func() { testLaneFault = nil }()

	primary := &conn.WebRTCConn{} // never dereferenced: testLaneFault short-circuits every NewLane call
	keys := &crypto.DerivedKeys{Confirm: bytes.Repeat([]byte{3}, 32)}
	senderPub, receiverPub := bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32)

	type result struct {
		ms     *transfer.MultiStream
		report *ParallelLaneReport
		err    error
	}
	resultCh := make(chan result, 1)
	go func() {
		ms, report, err := negotiateWebRTC(context.Background(), primary, clientStream, keys, senderPub, receiverPub, false, 3)
		resultCh <- result{ms, report, err}
	}()

	peerWrite := func(v webRTCParallelControl) {
		t.Helper()
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := peerStream.WriteFrame(webRTCParallelMessage, data); err != nil {
			t.Fatal(err)
		}
	}
	peerRead := func() webRTCParallelControl {
		t.Helper()
		kind, data, err := peerStream.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if kind != webRTCParallelMessage {
			t.Fatalf("unexpected frame kind %d", kind)
		}
		var v webRTCParallelControl
		if err := json.Unmarshal(data, &v); err != nil {
			t.Fatal(err)
		}
		return v
	}

	nonce := bytes.Repeat([]byte{9}, 32)
	peerWrite(webRTCParallelControl{Step: "hello", Version: 1, Count: 3, Nonce: nonce})
	if accept := peerRead(); accept.Step != "accept" || accept.Count != 3 {
		t.Fatalf("accept = %+v", accept)
	}
	for id := 1; id < 3; id++ {
		peerWrite(webRTCParallelControl{Step: "offer", ID: id})
	}
	for id := 1; id < 3; id++ {
		if answer := peerRead(); answer.Step != "answer" || answer.ID != id {
			t.Fatalf("answer = %+v", answer)
		}
	}
	peerWrite(webRTCParallelControl{Step: "ready", Mask: 0})
	if ready := peerRead(); ready.Step != "ready" || ready.Mask != 0 {
		t.Fatalf("ready = %+v", ready)
	}
	peerWrite(webRTCParallelControl{Step: "commit", Mask: 0})
	if committed := peerRead(); committed.Step != "committed" || committed.Mask != 0 {
		t.Fatalf("committed = %+v", committed)
	}

	var res result
	select {
	case res = <-resultCh:
	case <-time.After(5 * time.Second):
		t.Fatal("negotiateWebRTC did not return")
	}
	if res.err != nil {
		t.Fatalf("negotiateWebRTC error: %v", res.err)
	}
	if res.ms != nil {
		t.Fatal("expected no multi-stream when every extra lane failed")
	}
	report := res.report
	if report == nil {
		t.Fatal("expected a report")
	}
	if report.Requested != 3 || report.Accepted != 3 || report.Selected != 0 || report.Ours != 0 || report.Theirs != 0 {
		t.Fatalf("report = %+v", report)
	}
	if len(report.Failures) != 2 {
		t.Fatalf("failures = %+v", report.Failures)
	}
	classes := map[int]LaneFailureClass{}
	for _, f := range report.Failures {
		if f.Stage != stageCreate {
			t.Fatalf("failure %+v: stage = %q, want %q", f, f.Stage, stageCreate)
		}
		if f.Trace != nil || f.Pair != "" {
			t.Fatalf("failure %+v: expected no trace/pair for a create-stage failure", f)
		}
		classes[f.ID] = f.Class
	}
	if classes[1] != ClassTimeout {
		t.Fatalf("id 1 class = %s, want %s", classes[1], ClassTimeout)
	}
	if classes[2] != ClassEOF {
		t.Fatalf("id 2 class = %s, want %s", classes[2], ClassEOF)
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	assertNoAddressLikeStrings(t, string(data))
}
