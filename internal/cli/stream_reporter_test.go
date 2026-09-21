// SPDX-License-Identifier: MIT

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"
)

func TestStreamMachineOutputSeparatesPayloadAndHandoff(t *testing.T) {
	var output bytes.Buffer
	r := newStreamReporter(context.Background(), StreamConfig{Output: OutputConfig{Format: OutputJSON, EventWriter: &output}}, "rsync", "send", "send-client")
	r.code("23456789-placeholder")
	r.ready("")
	payload := []byte{0, 0xff, 'x', '\n'}
	if _, err := r.subprocessWriter("stdout", io.Discard).Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := r.finish(nil, 123, 456); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&output)
	var results int
	for decoder.More() {
		var event machineEvent
		if err := decoder.Decode(&event); err != nil {
			t.Fatal(err)
		}
		if event.Service != "rsync" || event.Mode != "send-client" || event.Role != "send" {
			t.Fatalf("missing stream identity: %s", event.Event)
		}
		if event.Event == "session" && (event.ShareURL != "" || event.AgentPrompt != "") {
			t.Fatal("stream event advertised a browser file receive URL")
		}
		if event.Event == "subprocess_output" && !bytes.Equal(event.OutputData, payload) {
			t.Fatal("subprocess bytes changed")
		}
		if event.Event == "result" {
			results++
			if event.BytesSent == nil || *event.BytesSent != 123 || event.BytesReceived == nil || *event.BytesReceived != 456 {
				t.Fatal("missing directional counters")
			}
		}
	}
	if results != 1 {
		t.Fatalf("terminal results: %d", results)
	}
}

func TestRsyncBridgeRejectsWrongCapability(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	token := bytes.Repeat([]byte{7}, 32)
	done := make(chan error, 1)
	go func() {
		conn, err := acceptRsyncBridge(ctx, listener, token)
		if err == nil {
			conn.Close()
		}
		done <- err
	}()
	bad, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	bad.SetDeadline(time.Now().Add(time.Second))
	bad.Write(bytes.Repeat([]byte{8}, 32))
	var ack [1]byte
	if _, err := bad.Read(ack[:]); err == nil {
		t.Fatal("bad capability accepted")
	}
	bad.Close()
	good, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer good.Close()
	good.SetDeadline(time.Now().Add(time.Second))
	if _, err := good.Write(token); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(good, ack[:]); err != nil || ack[0] != 1 {
		t.Fatalf("valid helper authentication: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
