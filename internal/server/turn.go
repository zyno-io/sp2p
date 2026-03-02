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
// before the server will issue TURN credentials. This makes scripted
// credential extraction impractical.
const turnMinWait = 5 * time.Second

// TURNCredentialGenerator produces short-lived HMAC-based TURN credentials
// compatible with the TURN REST API (draft-uberti-behave-turn-rest).
// TURN servers like coturn verify these credentials using the shared secret
// (configured with use-auth-secret).
type TURNCredentialGenerator struct {
	URLs   []string
	Secret string
	TTL    time.Duration
}

// Generate produces a fresh ICEServer with ephemeral credentials.
// The username is the Unix expiry timestamp; the credential is
// HMAC-SHA1(secret, username) encoded as base64.
func (g *TURNCredentialGenerator) Generate() signal.ICEServer {
	expiry := time.Now().Add(g.TTL).Unix()
	username := strconv.FormatInt(expiry, 10)
	mac := hmac.New(sha1.New, []byte(g.Secret))
	mac.Write([]byte(username))
	credential := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return signal.ICEServer{URLs: g.URLs, Username: username, Credential: credential}
}
