// SPDX-License-Identifier: MIT

package flow

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/zyno-io/sp2p/internal/conn"
	"github.com/zyno-io/sp2p/internal/crypto"
	"github.com/zyno-io/sp2p/internal/transfer"
)

const webRTCParallelMessage byte = 0x0e
const webRTCParallelLimit = 4

// This control is read only during explicitly opted-in, authenticated v3
// setup, before Session takes ownership of reads and receiver credits. SDP is
// encrypted, bounded, and never logged. Unknown controls still fail in Session.
type webRTCParallelControl struct {
	Step    string `json:"step"`
	Version int    `json:"version,omitempty"`
	Count   int    `json:"count,omitempty"`
	Nonce   []byte `json:"nonce,omitempty"`
	ID      int    `json:"id,omitempty"`
	SDP     string `json:"sdp,omitempty"`
	Mask    uint32 `json:"mask,omitempty"`
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

func negotiateWebRTC(ctx context.Context, primary *conn.WebRTCConn, encrypted *crypto.EncryptedStream,
	keys *crypto.DerivedKeys, senderPub, receiverPub []byte, sender bool, count int,
) (_ *transfer.MultiStream, err error) {
	if count < 1 || count > webRTCParallelLimit {
		return nil, fmt.Errorf("invalid WebRTC lane count")
	}
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
			return nil, err
		}
		if err = write(webRTCParallelControl{Step: "hello", Version: 1, Count: count, Nonce: nonce}); err != nil {
			return nil, err
		}
		accepted, e := read("accept")
		if e != nil {
			return nil, e
		}
		if accepted.Count < 1 || accepted.Count > count {
			return nil, fmt.Errorf("invalid WebRTC accepted count")
		}
		count = accepted.Count
	} else {
		hello, e := read("hello")
		if e != nil {
			return nil, e
		}
		if hello.Version != 1 || hello.Count < 1 || hello.Count > webRTCParallelLimit || len(hello.Nonce) != 32 {
			return nil, fmt.Errorf("invalid WebRTC parallel offer")
		}
		count = min(count, hello.Count)
		nonce = hello.Nonce
		if err = write(webRTCParallelControl{Step: "accept", Count: count}); err != nil {
			return nil, err
		}
	}
	if count == 1 {
		return nil, nil
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
		lane, e := primary.NewLane(sender)
		if e == nil {
			lanes[id] = lane
		}
		if !sender {
			offer, e := read("offer")
			if e != nil {
				return nil, e
			}
			if offer.ID != id || len(offer.SDP) > 12*1024 {
				return nil, fmt.Errorf("invalid WebRTC lane offer")
			}
			if lane != nil && (offer.SDP == "" || lane.SetDescription(offer.SDP, true) != nil) {
				lane.Conn.Close()
				lane.Conn.DiscardSetupInput()
				lanes[id] = nil
				lane = nil
			}
		}
		if lane != nil {
			gather.Add(1)
			go func(id int, lane *conn.WebRTCLane) {
				defer gather.Done()
				sdp, e := lane.Description(ctx, sender)
				if e == nil && len(sdp) <= 12*1024 {
					descriptions[id] = sdp
				}
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
			return nil, err
		}
	}
	if sender {
		for id := 1; id < count; id++ {
			answer, e := read("answer")
			if e != nil {
				return nil, e
			}
			if answer.ID != id || len(answer.SDP) > 12*1024 {
				return nil, fmt.Errorf("invalid WebRTC lane answer")
			}
			if lane := lanes[id]; lane != nil && (answer.SDP == "" || lane.SetDescription(answer.SDP, false) != nil) {
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
		if lane == nil || descriptions[id] == "" {
			continue
		}
		authenticate.Add(1)
		go func(id int, lane *conn.WebRTCLane) {
			defer authenticate.Done()
			if e := lane.Wait(authCtx); e != nil {
				return
			}
			laneKeys, e := crypto.DeriveWebRTCLaneKeys(keys.Confirm, nonce, id)
			if e != nil {
				return
			}
			selectLane, e := crypto.AuthenticateCandidate(authCtx, lane.Conn, laneKeys, senderPub, receiverPub, sender)
			if e != nil {
				return
			}
			if selectLane != nil {
				if e = selectLane(authCtx); e != nil {
					return
				}
			}
			if e = crypto.SendConfirmation(authCtx, lane.Conn, laneKeys, senderPub, receiverPub, sender); e != nil {
				return
			}
			writeKey, readKey := laneKeys.SenderToReceiver, laneKeys.ReceiverToSender
			if !sender {
				writeKey, readKey = readKey, writeKey
			}
			streams[id], _ = crypto.NewEncryptedStream(lane.Conn, writeKey, readKey)
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
			return nil, err
		}
		theirs, err = read("ready")
	} else {
		theirs, err = read("ready")
		if err == nil {
			err = write(webRTCParallelControl{Step: "ready", Mask: ours})
		}
	}
	if err != nil {
		return nil, err
	}
	allowed := uint32((1 << count) - 2)
	if theirs.Mask & ^allowed != 0 {
		return nil, fmt.Errorf("invalid WebRTC ready mask")
	}
	selected := ours & theirs.Mask
	if sender {
		if err = write(webRTCParallelControl{Step: "commit", Mask: selected}); err != nil {
			return nil, err
		}
		ack, e := read("committed")
		if e != nil {
			return nil, e
		}
		if ack.Mask != selected {
			return nil, fmt.Errorf("WebRTC commit mismatch")
		}
	} else {
		commit, e := read("commit")
		if e != nil {
			return nil, e
		}
		if commit.Mask != selected {
			return nil, fmt.Errorf("WebRTC commit mismatch")
		}
		if err = write(webRTCParallelControl{Step: "committed", Mask: selected}); err != nil {
			return nil, err
		}
	}
	if selected == 0 {
		return nil, nil
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
	return transfer.NewWebRTCMultiStream(active, connections), nil
}
