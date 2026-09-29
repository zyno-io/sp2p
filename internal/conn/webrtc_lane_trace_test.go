// SPDX-License-Identifier: MIT

package conn

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

var ipLikeTracePattern = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)

func newTestPrimary(t *testing.T, isSender bool) *WebRTCConn {
	t.Helper()
	pc, err := newOfferPeerConnection(webrtc.SettingEngine{}, webrtc.Configuration{}, false, isSender)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	return &WebRTCConn{pc: pc, receiveBudget: &webRTCReceiveBudget{parallel: true}}
}

// TestNewLaneTraceAndPairTypesOverRealConnection connects two extra lanes
// directly to each other — SDP exchanged with plain Go calls over loopback,
// the same non-trickle pattern NewLane itself relies on, no signaling
// server involved — and checks that Trace() records address-free
// connection/ICE/DataChannel transitions and that PairTypes() reports
// candidate *types* only.
func TestNewLaneTraceAndPairTypesOverRealConnection(t *testing.T) {
	senderPrimary := newTestPrimary(t, true)
	receiverPrimary := newTestPrimary(t, false)

	senderLane, err := senderPrimary.NewLane(true)
	if err != nil {
		t.Fatal(err)
	}
	defer senderLane.Conn.Close()
	receiverLane, err := receiverPrimary.NewLane(false)
	if err != nil {
		t.Fatal(err)
	}
	defer receiverLane.Conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	offer, err := senderLane.Description(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := receiverLane.SetDescription(offer, true); err != nil {
		t.Fatal(err)
	}
	answer, err := receiverLane.Description(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := senderLane.SetDescription(answer, false); err != nil {
		t.Fatal(err)
	}

	if err := senderLane.Wait(ctx); err != nil {
		t.Fatalf("sender lane did not open: %v", err)
	}
	if err := receiverLane.Wait(ctx); err != nil {
		t.Fatalf("receiver lane did not open: %v", err)
	}

	for name, lane := range map[string]*WebRTCLane{"sender": senderLane, "receiver": receiverLane} {
		trace := lane.Trace()
		var sawConn, sawICE, sawOpen bool
		for _, ev := range trace {
			if ev.MS < 0 {
				t.Fatalf("%s: negative trace offset: %+v", name, ev)
			}
			switch {
			case strings.HasPrefix(ev.Event, "conn="):
				sawConn = true
			case strings.HasPrefix(ev.Event, "ice="):
				sawICE = true
			case ev.Event == "dc=open":
				sawOpen = true
			}
			if ipLikeTracePattern.MatchString(ev.Event) {
				t.Fatalf("%s: trace event looks address-like: %q", name, ev.Event)
			}
		}
		if !sawConn || !sawICE || !sawOpen {
			t.Fatalf("%s: trace missing expected categories: %+v", name, trace)
		}

		pair := lane.PairTypes()
		if pair == "" {
			t.Fatalf("%s: expected a selected candidate pair", name)
		}
		if ipLikeTracePattern.MatchString(pair) {
			t.Fatalf("%s: pair types look address-like: %q", name, pair)
		}
		parts := strings.Split(pair, "/")
		if len(parts) != 2 {
			t.Fatalf("%s: pair %q is not local/remote", name, pair)
		}
		for _, part := range parts {
			switch part {
			case "host", "srflx", "prflx", "relay":
			default:
				t.Fatalf("%s: unexpected candidate type %q in pair %q", name, part, pair)
			}
		}
	}
}

// TestNewLaneSelfClosesOnLabelRejection wires a real (wrongly labeled)
// DataChannel from a plain, non-lane peer connection into a receiver lane
// and checks the lane records why it closed itself, matching the
// label/ordered/retransmits validation in NewLane's OnDataChannel handler.
func TestNewLaneSelfClosesOnLabelRejection(t *testing.T) {
	badPC, err := newOfferPeerConnection(webrtc.SettingEngine{}, webrtc.Configuration{}, false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer badPC.Close()
	if _, err := badPC.CreateDataChannel("wrong-label", nil); err != nil {
		t.Fatal(err)
	}

	receiverPrimary := newTestPrimary(t, false)
	receiverLane, err := receiverPrimary.NewLane(false)
	if err != nil {
		t.Fatal(err)
	}
	defer receiverLane.Conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	offer, err := badPC.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	complete := webrtc.GatheringCompletePromise(badPC)
	if err := badPC.SetLocalDescription(offer); err != nil {
		t.Fatal(err)
	}
	select {
	case <-complete:
	case <-ctx.Done():
		t.Fatal("gathering never completed")
	}
	if err := receiverLane.SetDescription(badPC.LocalDescription().SDP, true); err != nil {
		t.Fatal(err)
	}
	answer, err := receiverLane.Description(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := badPC.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: answer}); err != nil {
		t.Fatal(err)
	}

	select {
	case <-receiverLane.Conn.closed:
	case <-ctx.Done():
		t.Fatal("receiver lane never closed itself after a mislabeled DataChannel")
	}
	var found bool
	for _, ev := range receiverLane.Trace() {
		if ev.Event == "close=label_rejected" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a close=label_rejected trace event, got %+v", receiverLane.Trace())
	}
}
