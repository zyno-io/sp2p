# SP2P Signaling Protocol Analysis: Peer Type Identification

## Current State: No Peer Type Detection

The server currently **cannot distinguish** between browser and CLI clients. Both send identical messages.

## Message Structure

### 1. HELLO Message (Sender Registration)
**File:** `/Users/sean/Work/Signal24/OSS/sp2p/internal/signal/messages.go:34-37`

```go
type Hello struct {
    Version int `json:"version"`
}
```

**Sent by:** CLI (flow/send.go:48) and browser (web/src/main.ts:271)
**Contains:** Only protocol version, nothing to identify client type
**Server handler:** `/Users/sean/Work/Signal24/OSS/sp2p/internal/server/handler_signal.go:82-116`

### 2. JOIN Message (Receiver Registration)
**File:** `/Users/sean/Work/Signal24/OSS/sp2p/internal/signal/messages.go:59-63`

```go
type Join struct {
    Version   int    `json:"version"`
    SessionID string `json:"sessionId"`
}
```

**Sent by:** CLI (flow/receive.go:63) and browser (web/src/main.ts:580)
**Contains:** Only version and session ID
**Server handler:** `/Users/sean/Work/Signal24/OSS/sp2p/internal/server/handler_signal.go:118-153`

### 3. WELCOME Message (Server Response)
**File:** `/Users/sean/Work/Signal24/OSS/sp2p/internal/signal/messages.go:39-44`

```go
type Welcome struct {
    SessionID     string      `json:"sessionId"`
    ICEServers    []ICEServer `json:"iceServers,omitempty"`
    TURNAvailable bool        `json:"turnAvailable,omitempty"`
}
```

**Sent by:** Server to both sender and receiver
**Does NOT include:** Any peer type information
**Could include:** Peer capabilities

### 4. PEER-JOINED Message
**File:** `/Users/sean/Work/Signal24/OSS/sp2p/internal/signal/messages.go:65-66`

```go
type PeerJoined struct{}
```

**Sent by:** Server notifies sender when receiver joins (handler_signal.go:148)
**Contains:** Empty payload - no information about joining peer
**Could include:** Peer type/capabilities

## Server-Side Session Storage
**File:** `/Users/sean/Work/Signal24/OSS/sp2p/internal/server/session.go:35-44`

```go
type Session struct {
    ID        string
    IP        string                           // Client IP for rate limiting
    CreatedAt time.Time
    LastSeen  time.Time
    Sender    *websocket.Conn                  // Direct connection object
    receiver  atomic.Pointer[websocket.Conn]   // Direct connection object
    joinedAt  atomic.Int64                     // unix nanos when receiver joined
    fileInfo  atomic.Pointer[string]           // encrypted file metadata
}
```

**Current tracking:** Only raw WebSocket connections, no client metadata
**Missing:** Client type, capabilities, peer address info

## Peer Connection Methods
**File:** `/Users/sean/Work/Signal24/OSS/sp2p/internal/conn/direct.go`

Three connection methods are available:
1. **Direct TCP** (lines 12-79): CLI sends/receives TCP endpoint via `TypeDirect` message
2. **WebRTC Data Channel**: Both browser and CLI use WebRTC for P2P
3. **TURN Relay**: Fallback when direct connection fails

### DirectEndpoint Message
**File:** `/Users/sean/Work/Signal24/OSS/sp2p/internal/signal/messages.go:86-89`

```go
type DirectEndpoint struct {
    TCP string `json:"tcp,omitempty"` // host:port for direct TCP
}
```

**Sent by:** CLI as TypeDirect message (likely in flow package)
**Browser:** Does NOT send this (cannot do TCP from WebSocket)
**Current limitation:** Server has no way to warn browsers about TCP endpoints

## Web Client Identity
**Files:** 
- `/Users/sean/Work/Signal24/OSS/sp2p/web/src/signal.ts:41-51` (SignalClient.connect)
- `/Users/sean/Work/Signal24/OSS/sp2p/web/src/main.ts:267-271` (initSend hello)
- `/Users/sean/Work/Signal24/OSS/sp2p/web/src/main.ts:580` (initReceive join)

**Current approach:**
- Browser sends generic `hello` with only version
- Browser sends generic `join` with only version and sessionId
- No UserAgent or client type in any signal message
- Browser capabilities (WebRTC only, no TCP) never communicated to server/peer

## CLI Client Identity
**Files:**
- `/Users/sean/Work/Signal24/OSS/sp2p/internal/flow/send.go:48` (Send hello)
- `/Users/sean/Work/Signal24/OSS/sp2p/internal/flow/receive.go:63-68` (Receive join)

**Current approach:**
- CLI sends generic `hello` with only version
- CLI sends generic `join` with only version and sessionId
- Later sends `TypeDirect` with TCP endpoint
- No explicit "I'm a CLI" identification

## Key Problem: TCP Incompatibility Detection

### Current Issue
- Browser cannot listen/connect TCP (sandboxed by Web APIs)
- CLI can do TCP, sends endpoint via `TypeDirect`
- Server relays messages but doesn't know if receiver can handle TCP
- If CLI (sender) sends TCP endpoint to browser (receiver), receiver silently ignores it
- Users experience mysterious TCP fallback to WebRTC without understanding why

### Example Problematic Flow
1. CLI sender registers with `Hello` (no type indicator)
2. Browser receiver joins with `Join` (no type indicator)
3. Server sends `PeerJoined` to sender (no info about browser)
4. CLI listens on TCP, sends `DirectEndpoint` with TCP address
5. Browser receives `DirectEndpoint` but cannot use TCP - falls back to WebRTC
6. Peer doesn't know why direct TCP failed vs direct connection established

## Proposed Solution: Add Peer Type to Messages

### Option A: Extend HELLO and JOIN
```go
type Hello struct {
    Version     int    `json:"version"`
    ClientType  string `json:"clientType"`  // "cli" or "browser"
    Capabilities []string `json:"capabilities,omitempty"` // ["tcp", "webrtc", "turn"]
}

type Join struct {
    Version      int    `json:"version"`
    SessionID    string `json:"sessionId"`
    ClientType   string `json:"clientType"`  // "cli" or "browser"
    Capabilities []string `json:"capabilities,omitempty"`
}
```

### Option B: Extend WELCOME and PEER-JOINED
```go
type Welcome struct {
    SessionID      string      `json:"sessionId"`
    ICEServers     []ICEServer `json:"iceServers,omitempty"`
    TURNAvailable  bool        `json:"turnAvailable,omitempty"`
    PeerType       string      `json:"peerType,omitempty"`       // "cli" or "browser"
    PeerCapabilities []string  `json:"peerCapabilities,omitempty"` // ["tcp", "webrtc"]
}

type PeerJoined struct {
    PeerType       string   `json:"peerType"`       // "cli" or "browser"
    Capabilities   []string `json:"capabilities"`   // ["tcp", "webrtc", "turn"]
}
```

### Option C: Hybrid Approach (RECOMMENDED)
- Add to `Hello`/`Join` so server can track in Session object
- Add to `PeerJoined` so peer knows what they're connected to
- Add to `Welcome` for redundancy and HTTP-based peer info

## Implementation Points

### TypeScript (Browser)
**File:** `/Users/sean/Work/Signal24/OSS/sp2p/web/src/main.ts`

Line 271 (initSend):
```typescript
sigClient.send("hello", { 
    version: PROTOCOL_VERSION,
    clientType: "browser",
    capabilities: ["webrtc"]  // or detect ["webrtc", "turn"] based on features
});
```

Line 580 (initReceive):
```typescript
sigClient.send("join", { 
    version: PROTOCOL_VERSION, 
    sessionId,
    clientType: "browser",
    capabilities: ["webrtc"]
});
```

### Go Server
**File:** `/Users/sean/Work/Signal24/OSS/sp2p/internal/server/session.go`

Extend Session struct:
```go
type Session struct {
    ID               string
    IP               string
    CreatedAt        time.Time
    LastSeen         time.Time
    Sender           *websocket.Conn
    SenderType       string   // "cli" or "browser"
    SenderCapabilities []string
    receiver         atomic.Pointer[websocket.Conn]
    ReceiverType     string   // "cli" or "browser"
    ReceiverCapabilities []string
    // ... rest unchanged
}
```

**File:** `/Users/sean/Work/Signal24/OSS/sp2p/internal/server/handler_signal.go`

In `handleSender` (line 82), after parsing Hello:
```go
var hello signal.Hello
// ... existing parsing
session.SenderType = hello.ClientType
session.SenderCapabilities = hello.Capabilities
```

In `handleReceiver` (line 118), after parsing Join, before `PeerJoined`:
```go
var join signal.Join
// ... existing parsing
session.ReceiverType = join.ClientType
session.ReceiverCapabilities = join.Capabilities

// Then notify sender with peer type:
sendMessage(ctx, session.Sender, signal.TypePeerJoined, signal.PeerJoined{
    PeerType: join.ClientType,
    Capabilities: join.Capabilities,
})
```

### Go Client
**File:** `/Users/sean/Work/Signal24/OSS/sp2p/internal/flow/send.go` (line 48)

```go
if err := sigClient.Send(ctx, signal.TypeHello, signal.Hello{
    Version: signal.ProtocolVersion,
    ClientType: "cli",
    Capabilities: []string{"tcp", "webrtc", "turn"},
}); err != nil {
    return fmt.Errorf("sending hello: %w", err)
}
```

**File:** `/Users/sean/Work/Signal24/OSS/sp2p/internal/flow/receive.go` (line 63)

```go
if err := sigClient.Send(ctx, signal.TypeJoin, signal.Join{
    Version: signal.ProtocolVersion,
    SessionID: sessionID,
    ClientType: "cli",
    Capabilities: []string{"tcp", "webrtc", "turn"},
}); err != nil {
    return nil, fmt.Errorf("sending join: %w", err)
}
```

## Benefits of Adding Peer Type

1. **Browser Knows it's Talking to CLI**: Can log "Connected to CLI device" or show different UI
2. **CLI Knows it's Talking to Browser**: Can skip TCP attempt, avoid wasted time/bandwidth
3. **Server Can Track**: Session knows sender/receiver types for debugging/metrics
4. **Future Extensibility**: Capabilities array allows adding new connection methods
5. **Better Error Messages**: "Direct TCP failed (peer is browser, cannot listen on ports)"
6. **Bandwidth Savings**: CLI-to-browser connections skip pointless TCP handshake attempts
7. **Metrics**: Track connection patterns (cli-to-cli vs browser-to-browser vs mixed)

## Backward Compatibility Considerations

- Both fields should be optional (with defaults based on absence)
- Server should handle missing ClientType/Capabilities gracefully
- Server can infer: if DirectEndpoint received → likely CLI; if never received → likely browser
- Could use version negotiation if needed for future protocol changes
