// SPDX-License-Identifier: MIT

package signal

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"

	"github.com/coder/websocket"
)

// Client is a WebSocket signaling client.
type Client struct {
	conn   *websocket.Conn
	mu     sync.Mutex
	cancel context.CancelFunc

	// Incoming receives all messages from the server.
	// Use Subscribe() for type-filtered delivery when multiple goroutines
	// need to read from the same client concurrently.
	Incoming chan *Envelope
	done     chan struct{}

	subsMu sync.Mutex
	subs   map[string][]chan *Envelope
}

// Connect establishes a WebSocket connection to the signaling server.
// The provided ctx is only used for dialing; the read loop runs independently
// until Close is called.
func Connect(ctx context.Context, serverURL string) (*Client, error) {
	conn, _, err := websocket.Dial(ctx, serverURL, nil)
	if err != nil {
		return nil, fmt.Errorf("connecting to signaling server: %w", err)
	}
	conn.SetReadLimit(64 * 1024) // 64 KB max message

	// Create a separate context for the read loop so it isn't killed
	// by a dial timeout.
	readCtx, cancel := context.WithCancel(context.Background())

	c := &Client{
		conn:     conn,
		cancel:   cancel,
		Incoming: make(chan *Envelope, 32),
		done:     make(chan struct{}),
		subs:     make(map[string][]chan *Envelope),
	}
	go c.readLoop(readCtx)
	return c, nil
}

func (c *Client) readLoop(ctx context.Context) {
	defer close(c.done)
	defer close(c.Incoming)
	for {
		_, data, err := c.conn.Read(ctx)
		if err != nil {
			return
		}
		var env Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			continue
		}

		// Deliver to type-specific subscribers first.
		delivered := false
		c.subsMu.Lock()
		if chs, ok := c.subs[env.Type]; ok && len(chs) > 0 {
			delivered = true
			for _, ch := range chs {
				select {
				case ch <- &env:
				default:
					log.Printf("signal: dropping %s message (subscriber full)", env.Type)
				}
			}
		}
		c.subsMu.Unlock()

		// If no subscriber handled it, deliver to the general Incoming channel.
		if !delivered {
			select {
			case c.Incoming <- &env:
			case <-ctx.Done():
				return
			}
		}
	}
}

// Subscribe returns a channel that receives messages of the given type.
// Subscribed types are no longer delivered to the Incoming channel.
// Call Unsubscribe when done.
func (c *Client) Subscribe(msgType string) chan *Envelope {
	ch := make(chan *Envelope, 16)
	c.subsMu.Lock()
	c.subs[msgType] = append(c.subs[msgType], ch)
	c.subsMu.Unlock()
	return ch
}

// Unsubscribe removes a subscription channel for a message type.
func (c *Client) Unsubscribe(msgType string, ch chan *Envelope) {
	c.subsMu.Lock()
	defer c.subsMu.Unlock()
	chs := c.subs[msgType]
	for i, existing := range chs {
		if existing == ch {
			c.subs[msgType] = append(chs[:i], chs[i+1:]...)
			break
		}
	}
}

// Send sends a typed message to the server.
func (c *Client) Send(ctx context.Context, msgType string, payload any) error {
	env, err := NewEnvelope(msgType, payload)
	if err != nil {
		return err
	}
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.Write(ctx, websocket.MessageText, data)
}

// Close closes the WebSocket connection and stops the read loop.
func (c *Client) Close() error {
	c.cancel()
	return c.conn.Close(websocket.StatusNormalClosure, "")
}

// Done returns a channel that is closed when the connection is lost.
func (c *Client) Done() <-chan struct{} {
	return c.done
}
