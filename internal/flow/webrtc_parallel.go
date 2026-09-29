// SPDX-License-Identifier: MIT

package flow

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/zyno-io/sp2p/internal/conn"
	"github.com/zyno-io/sp2p/internal/crypto"
	"github.com/zyno-io/sp2p/internal/transfer"
)

const webRTCParallelMessage byte = 0x0e
const webRTCParallelLimit = 8

// webRTCParallelLegacyLimit is the largest lane count already-released peers
// understand in the plain hello.count field. A sender wanting more lanes
// caps count at this value and carries the real request in Max instead, so
// old receivers — which ignore unknown JSON fields — still see a valid
// count <= 4 and negotiate normally.
const webRTCParallelLegacyLimit = 4

// This control is read only during explicitly opted-in, authenticated v3
// setup, before Session takes ownership of reads and receiver credits. SDP is
// encrypted, bounded, and never logged. Unknown controls still fail in Session.
type webRTCParallelControl struct {
	Step    string `json:"step"`
	Version int    `json:"version,omitempty"`
	Count   int    `json:"count,omitempty"`
	// Max carries a request above webRTCParallelLegacyLimit. It is only ever
	// sent alongside Count == webRTCParallelLegacyLimit, and only on hello.
	// Old receivers ignore this unknown field and accept the plain count.
	Max   int    `json:"max,omitempty"`
	Nonce []byte `json:"nonce,omitempty"`
	ID    int    `json:"id,omitempty"`
	SDP   string `json:"sdp,omitempty"`
	Mask  uint32 `json:"mask,omitempty"`
}

func parseWebRTCParallelControl(kind byte, data []byte, step string) (webRTCParallelControl, error) {
	var value webRTCParallelControl
	if kind != webRTCParallelMessage || len(data) > 16*1024 {
		return value, fmt.Errorf("unexpected WebRTC setup control")
	}
	if err := json.Unmarshal(data, &value); err != nil || value.Step != step {
		return value, fmt.Errorf("invalid WebRTC setup step")
	}
	return value, nil
}

// helloCountAndMax splits a desired lane count into the hello.count and
// hello.max fields. Requests at or below the legacy limit are sent exactly
// as before, with Max omitted; larger requests keep count at the legacy cap
// and carry the real request in Max, so old receivers — which ignore
// unknown fields — still see a plain, understood count.
func helloCountAndMax(count int) (helloCount, helloMax int) {
	if count > webRTCParallelLegacyLimit {
		return webRTCParallelLegacyLimit, count
	}
	return count, 0
}

// webRTCParallelHello builds the sender's hello for a desired lane count.
func webRTCParallelHello(count int, nonce []byte) webRTCParallelControl {
	helloCount, helloMax := helloCountAndMax(count)
	return webRTCParallelControl{Step: "hello", Version: 1, Count: helloCount, Max: helloMax, Nonce: nonce}
}

// acceptWebRTCParallelHello validates a hello and returns the lane count a
// receiver with the given limit accepts.
func acceptWebRTCParallelHello(hello webRTCParallelControl, limit int) (int, error) {
	requested, err := resolveHelloRequest(hello)
	if err != nil {
		return 0, err
	}
	return min(limit, requested), nil
}

// resolveHelloRequest validates an incoming hello and returns the lane count
// actually being requested. The existing 1..4 count bounds and nonce length
// always apply; an optional Max of 5..8 is only valid alongside the legacy
// cap count and then replaces it as the request.
func resolveHelloRequest(hello webRTCParallelControl) (int, error) {
	if hello.Version != 1 || hello.Count < 1 || hello.Count > webRTCParallelLegacyLimit || len(hello.Nonce) != 32 {
		return 0, fmt.Errorf("invalid WebRTC parallel offer")
	}
	if hello.Max == 0 {
		return hello.Count, nil
	}
	if hello.Max < webRTCParallelLegacyLimit+1 || hello.Max > webRTCParallelLimit || hello.Count != webRTCParallelLegacyLimit {
		return 0, fmt.Errorf("invalid WebRTC parallel offer")
	}
	return hello.Max, nil
}

// LaneFailureClass is a small, fixed vocabulary for why a lane never made it
// into the selected set. Every diagnostic surface (the JSON parallel_lanes
// event, docs, the man page) only ever needs to understand these five
// buckets — raw Go/Pion error text, which can contain addresses, never
// crosses into a report; it only ever reaches OnVerbose.
type LaneFailureClass string

const (
	ClassTimeout  LaneFailureClass = "timeout"
	ClassEOF      LaneFailureClass = "eof"
	ClassClosed   LaneFailureClass = "closed"
	ClassMismatch LaneFailureClass = "mismatch"
	ClassError    LaneFailureClass = "error"
)

// laneStage is the fixed set of points where a lane can silently drop out of
// setup. Keep this in sync with docs/parallel-webrtc.md and man/sp2p.1.
const (
	stageCreate           = "create"
	stageGather           = "gather"
	stageSDPSize          = "sdp-size"
	stagePeerOfferEmpty   = "peer-offer-empty"
	stageSetRemoteOffer   = "set-remote-offer"
	stagePeerAnswerEmpty  = "peer-answer-empty"
	stageSetRemoteAnswer  = "set-remote-answer"
	stageConnectTimeout   = "connect-timeout"
	stageClosedBeforeOpen = "closed-before-open"
	stageAuthChallenge    = "auth-challenge"
	stageAuthProof        = "auth-proof"
	stageSelect           = "select"
	stageConfirm          = "confirm"
	stagePeerNotReady     = "peer-not-ready"
)

// LaneFailure records why one requested-and-accepted lane never made it into
// the selected set. Trace and Pair are address-free (see
// conn.WebRTCLane.Trace/PairTypes): protocol-level states and candidate
// *types* only, never IPs, ports, ufrags, or SDP.
type LaneFailure struct {
	ID    int                   `json:"id"`
	Stage string                `json:"stage"`
	Class LaneFailureClass      `json:"class"`
	Trace []conn.LaneTraceEvent `json:"trace,omitempty"`
	Pair  string                `json:"pair,omitempty"`
}

// ParallelLaneReport summarizes a completed parallel WebRTC negotiation,
// including any lane that was requested and accepted but never selected. It
// is safe to log or emit as JSON: no IPs, ports, ufrags, transfer codes, or
// SDP ever end up in it — see internal/flow's ParallelLaneReporter and
// internal/cli's parallel_lanes event.
type ParallelLaneReport struct {
	Requested int           `json:"requested"`
	Accepted  int           `json:"accepted"`
	Ours      uint32        `json:"ours"`
	Theirs    uint32        `json:"theirs"`
	Selected  uint32        `json:"selected"`
	SetupMS   int64         `json:"setup_ms"`
	Failures  []LaneFailure `json:"failures,omitempty"`
}

// classifyLaneError buckets an error into the fixed Class vocabulary. It may
// read err.Error() to match a handful of known, fixed substrings, but the
// raw text itself is never retained or returned — only which one of the five
// buckets applies.
func classifyLaneError(err error) LaneFailureClass {
	switch {
	case err == nil:
		return ClassError
	case errors.Is(err, context.DeadlineExceeded):
		return ClassTimeout
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return ClassEOF
	case errors.Is(err, conn.ErrLaneClosed), errors.Is(err, net.ErrClosed):
		return ClassClosed
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "mismatch"), strings.Contains(msg, "authentication failed"),
		strings.Contains(msg, "selection failed"), strings.Contains(msg, "invalid candidate"):
		return ClassMismatch
	case strings.Contains(msg, "closed"):
		return ClassClosed
	default:
		return ClassError
	}
}

// laneFailures accumulates LaneFailure entries from concurrent setup and
// authentication goroutines.
type laneFailures struct {
	mu   sync.Mutex
	list []LaneFailure
}

func (f *laneFailures) addErr(id int, stage string, err error, trace []conn.LaneTraceEvent, pair string) {
	f.addClass(id, stage, classifyLaneError(err), trace, pair)
}

func (f *laneFailures) addClass(id int, stage string, class LaneFailureClass, trace []conn.LaneTraceEvent, pair string) {
	f.mu.Lock()
	f.list = append(f.list, LaneFailure{ID: id, Stage: stage, Class: class, Trace: trace, Pair: pair})
	f.mu.Unlock()
}

func (f *laneFailures) snapshot() []LaneFailure {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.list) == 0 {
		return nil
	}
	out := make([]LaneFailure, len(f.list))
	copy(out, f.list)
	return out
}

// stageForWaitError distinguishes a lane that never connected in time from
// one that closed (self-closed, or its peer connection failed) before its
// DataChannel opened.
func stageForWaitError(err error) string {
	if errors.Is(err, conn.ErrLaneClosed) {
		return stageClosedBeforeOpen
	}
	return stageConnectTimeout
}

// testLaneFault, when set by a test in this package, forces primary.NewLane
// to appear to fail for a given lane id at the "create" stage without any
// real WebRTC connection — the one discard site reachable without a lane
// ever having been created. Nil in production.
var testLaneFault func(id int) error

func negotiateWebRTC(ctx context.Context, primary *conn.WebRTCConn, encrypted *crypto.EncryptedStream,
	keys *crypto.DerivedKeys, senderPub, receiverPub []byte, sender bool, count int,
) (_ *transfer.MultiStream, _ *ParallelLaneReport, err error) {
	if count < 1 || count > webRTCParallelLimit {
		return nil, nil, fmt.Errorf("invalid WebRTC lane count")
	}
	requested := count
	started := time.Now()
	failures := &laneFailures{}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	fired := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { primary.SetDeadline(time.Now()); close(fired) })
	defer func() {
		if !stop() {
			<-fired
		}
		primary.SetDeadline(time.Time{})
	}()
	write := func(value webRTCParallelControl) error {
		data, e := json.Marshal(value)
		if e != nil {
			return e
		}
		if len(data) > 16*1024 {
			return fmt.Errorf("WebRTC setup control too large")
		}
		return encrypted.WriteFrame(webRTCParallelMessage, data)
	}
	read := func(step string) (webRTCParallelControl, error) {
		kind, data, e := encrypted.ReadFrame()
		if e != nil {
			return webRTCParallelControl{}, e
		}
		return parseWebRTCParallelControl(kind, data, step)
	}
	var nonce []byte
	if sender {
		nonce = make([]byte, 32)
		if _, err = rand.Read(nonce); err != nil {
			return nil, nil, err
		}
		if err = write(webRTCParallelHello(count, nonce)); err != nil {
			return nil, nil, err
		}
		accepted, e := read("accept")
		if e != nil {
			return nil, nil, e
		}
		if accepted.Count < 1 || accepted.Count > count {
			return nil, nil, fmt.Errorf("invalid WebRTC accepted count")
		}
		count = accepted.Count
	} else {
		hello, e := read("hello")
		if e != nil {
			return nil, nil, e
		}
		count, e = acceptWebRTCParallelHello(hello, count)
		if e != nil {
			return nil, nil, e
		}
		nonce = hello.Nonce
		if err = write(webRTCParallelControl{Step: "accept", Count: count}); err != nil {
			return nil, nil, err
		}
	}
	if count == 1 {
		return nil, nil, nil
	}

	lanes := make([]*conn.WebRTCLane, count)
	keep := uint32(0)
	var gather sync.WaitGroup
	defer func() {
		if err != nil {
			cancel()
		}
		for id, lane := range lanes {
			if lane != nil && (err != nil || keep&(1<<id) == 0) {
				lane.Conn.Close()
			}
		}
		gather.Wait()
		for id, lane := range lanes {
			if lane != nil && (err != nil || keep&(1<<id) == 0) {
				lane.Conn.DiscardSetupInput()
			}
		}
	}()
	descriptions := make([]string, count)
	for id := 1; id < count; id++ {
		var lane *conn.WebRTCLane
		var e error
		if testLaneFault != nil {
			e = testLaneFault(id)
		}
		if e == nil {
			lane, e = primary.NewLane(sender)
		}
		if e != nil {
			failures.addErr(id, stageCreate, e, nil, "")
		} else {
			lanes[id] = lane
		}
		if !sender {
			offer, e := read("offer")
			if e != nil {
				return nil, nil, e
			}
			if offer.ID != id || len(offer.SDP) > 12*1024 {
				return nil, nil, fmt.Errorf("invalid WebRTC lane offer")
			}
			if lane != nil {
				if offer.SDP == "" {
					failures.addClass(id, stagePeerOfferEmpty, ClassClosed, lane.Trace(), lane.PairTypes())
					lane.Conn.Close()
					lane.Conn.DiscardSetupInput()
					lanes[id] = nil
					lane = nil
				} else if e := lane.SetDescription(offer.SDP, true); e != nil {
					failures.addErr(id, stageSetRemoteOffer, e, lane.Trace(), lane.PairTypes())
					lane.Conn.Close()
					lane.Conn.DiscardSetupInput()
					lanes[id] = nil
					lane = nil
				}
			}
		}
		if lane != nil {
			gather.Add(1)
			go func(id int, lane *conn.WebRTCLane) {
				defer gather.Done()
				sdp, e := lane.Description(ctx, sender)
				if e != nil {
					failures.addErr(id, stageGather, e, lane.Trace(), lane.PairTypes())
					return
				}
				if len(sdp) > 12*1024 {
					failures.addClass(id, stageSDPSize, ClassMismatch, lane.Trace(), lane.PairTypes())
					return
				}
				descriptions[id] = sdp
			}(id, lane)
		}
	}
	gather.Wait()
	step := "answer"
	if sender {
		step = "offer"
	}
	for id := 1; id < count; id++ {
		if err = write(webRTCParallelControl{Step: step, ID: id, SDP: descriptions[id]}); err != nil {
			return nil, nil, err
		}
	}
	if sender {
		for id := 1; id < count; id++ {
			answer, e := read("answer")
			if e != nil {
				return nil, nil, e
			}
			if answer.ID != id || len(answer.SDP) > 12*1024 {
				return nil, nil, fmt.Errorf("invalid WebRTC lane answer")
			}
			lane := lanes[id]
			if lane == nil {
				continue
			}
			if answer.SDP == "" {
				failures.addClass(id, stagePeerAnswerEmpty, ClassClosed, lane.Trace(), lane.PairTypes())
				lane.Conn.Close()
				lane.Conn.DiscardSetupInput()
				lanes[id] = nil
			} else if e := lane.SetDescription(answer.SDP, false); e != nil {
				failures.addErr(id, stageSetRemoteAnswer, e, lane.Trace(), lane.PairTypes())
				lane.Conn.Close()
				lane.Conn.DiscardSetupInput()
				lanes[id] = nil
			}
		}
	}

	authCtx, authCancel := context.WithTimeout(ctx, 8*time.Second)
	defer authCancel()
	streams := make([]transfer.FrameReadWriter, count)
	var authenticate sync.WaitGroup
	for id := 1; id < count; id++ {
		lane := lanes[id]
		if lane == nil {
			continue
		}
		if descriptions[id] == "" {
			// Description gathering already recorded why (stageGather /
			// stageSDPSize) or the lane was never asked to gather at all
			// (sender: no description was requested this round).
			continue
		}
		authenticate.Add(1)
		go func(id int, lane *conn.WebRTCLane) {
			defer authenticate.Done()
			if e := lane.Wait(authCtx); e != nil {
				failures.addErr(id, stageForWaitError(e), e, lane.Trace(), lane.PairTypes())
				return
			}
			laneKeys, e := crypto.DeriveWebRTCLaneKeys(keys.Confirm, nonce, id)
			if e != nil {
				failures.addErr(id, stageAuthChallenge, e, lane.Trace(), lane.PairTypes())
				return
			}
			selectLane, e := crypto.AuthenticateCandidate(authCtx, lane.Conn, laneKeys, senderPub, receiverPub, sender)
			if e != nil {
				failures.addErr(id, stageAuthProof, e, lane.Trace(), lane.PairTypes())
				return
			}
			if selectLane != nil {
				if e = selectLane(authCtx); e != nil {
					failures.addErr(id, stageSelect, e, lane.Trace(), lane.PairTypes())
					return
				}
			}
			if e = crypto.SendConfirmation(authCtx, lane.Conn, laneKeys, senderPub, receiverPub, sender); e != nil {
				failures.addErr(id, stageConfirm, e, lane.Trace(), lane.PairTypes())
				return
			}
			writeKey, readKey := laneKeys.SenderToReceiver, laneKeys.ReceiverToSender
			if !sender {
				writeKey, readKey = readKey, writeKey
			}
			stream, e := crypto.NewEncryptedStream(lane.Conn, writeKey, readKey)
			if e != nil {
				failures.addErr(id, stageConfirm, e, lane.Trace(), lane.PairTypes())
				return
			}
			streams[id] = stream
		}(id, lane)
	}
	authenticate.Wait()
	var ours uint32
	for id := 1; id < count; id++ {
		if streams[id] != nil {
			ours |= 1 << id
		}
	}
	var theirs webRTCParallelControl
	if sender {
		if err = write(webRTCParallelControl{Step: "ready", Mask: ours}); err != nil {
			return nil, nil, err
		}
		theirs, err = read("ready")
	} else {
		theirs, err = read("ready")
		if err == nil {
			err = write(webRTCParallelControl{Step: "ready", Mask: ours})
		}
	}
	if err != nil {
		return nil, nil, err
	}
	allowed := uint32((1 << count) - 2)
	if theirs.Mask & ^allowed != 0 {
		return nil, nil, fmt.Errorf("invalid WebRTC ready mask")
	}
	selected := ours & theirs.Mask
	if sender {
		if err = write(webRTCParallelControl{Step: "commit", Mask: selected}); err != nil {
			return nil, nil, err
		}
		ack, e := read("committed")
		if e != nil {
			return nil, nil, e
		}
		if ack.Mask != selected {
			return nil, nil, fmt.Errorf("WebRTC commit mismatch")
		}
	} else {
		commit, e := read("commit")
		if e != nil {
			return nil, nil, e
		}
		if commit.Mask != selected {
			return nil, nil, fmt.Errorf("WebRTC commit mismatch")
		}
		if err = write(webRTCParallelControl{Step: "committed", Mask: selected}); err != nil {
			return nil, nil, err
		}
	}
	// A lane we ourselves got working but the peer's ready mask excluded is
	// a discard site we cannot see the other side of: record it as a
	// mismatch between our view and theirs, using our own trace/pair.
	for id := 1; id < count; id++ {
		if ours&(1<<id) != 0 && selected&(1<<id) == 0 {
			var trace []conn.LaneTraceEvent
			var pair string
			if lane := lanes[id]; lane != nil {
				trace, pair = lane.Trace(), lane.PairTypes()
			}
			failures.addClass(id, stagePeerNotReady, ClassMismatch, trace, pair)
		}
	}
	report := &ParallelLaneReport{
		Requested: requested,
		Accepted:  count,
		Ours:      ours,
		Theirs:    theirs.Mask,
		Selected:  selected,
		SetupMS:   time.Since(started).Milliseconds(),
		Failures:  failures.snapshot(),
	}
	if selected == 0 {
		return nil, report, nil
	}
	keep = selected
	active := []transfer.FrameReadWriter{encrypted}
	connections := []transfer.MultiStreamConn{primary}
	primary.SetSendBufferLimit(1024 * 1024)
	for id := 1; id < count; id++ {
		if selected&(1<<id) == 0 {
			continue
		}
		lanes[id].Conn.SetSendBufferLimit(1024 * 1024)
		active = append(active, streams[id])
		connections = append(connections, lanes[id].Conn)
	}
	return transfer.NewWebRTCMultiStream(active, connections), report, nil
}
