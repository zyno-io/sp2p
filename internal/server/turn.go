// SPDX-License-Identifier: MIT

package server

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"strconv"
	"time"

	"github.com/zyno-io/sp2p/internal/signal"
)

// turnMinWait is the minimum time that must elapse after a receiver joins
// before the server will issue TURN credentials. This is retry pacing only;
// public deployments also need allocation, bandwidth, and destination quotas.
const turnMinWait = 5 * time.Second

// TURNCredentialGenerator produces short-lived HMAC-based TURN credentials
// compatible with the TURN REST API (draft-uberti-behave-turn-rest).
// TURN servers like coturn verify these credentials using the shared secret
// (configured with use-auth-secret).
type TURNCredentialGenerator struct {
	URLs   []string
	Secret string
	TTL    time.Duration

	// onGenerate, when set, is called synchronously at the start of every
	// Generate call. It exists purely so tests can count real Generate
	// calls directly, to detect whether session.turnOnce actually
	// suppressed a repeat issuance: Generate's own output is only as
	// distinguishable as its one-second (Unix timestamp) resolution — two
	// calls within the same wall-clock second produce byte-identical
	// output whether or not caching ran, so comparing credentials alone
	// can't tell a working cache from a broken one in a fast test. Nil in
	// production.
	onGenerate func()
}

// Generate produces a fresh ICEServer with ephemeral credentials.
// The username is the Unix expiry timestamp; the credential is
// HMAC-SHA1(secret, username) encoded as base64.
func (g *TURNCredentialGenerator) Generate(sessionID ...string) signal.ICEServer {
	if g.onGenerate != nil {
		g.onGenerate()
	}
	expiry := time.Now().Add(g.TTL).Unix()
	username := strconv.FormatInt(expiry, 10)
	if len(sessionID) != 0 {
		username += ":" + sessionID[0]
	}
	mac := hmac.New(sha1.New, []byte(g.Secret))
	mac.Write([]byte(username))
	credential := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return signal.ICEServer{URLs: g.URLs, Username: username, Credential: credential}
}
