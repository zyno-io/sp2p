// SPDX-License-Identifier: MIT

package server

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"strconv"
	"testing"
	"time"
)

func TestTURNCredentialGenerator_Generate(t *testing.T) {
	secret := "my-turn-secret"
	ttl := 24 * time.Hour
	urls := []string{"turn:relay.example.com:3478", "turns:relay.example.com:5349"}

	gen := &TURNCredentialGenerator{
		URLs:   urls,
		Secret: secret,
		TTL:    ttl,
	}

	before := time.Now()
	ice := gen.Generate()
	after := time.Now()

	// URLs are passed through.
	if len(ice.URLs) != 2 || ice.URLs[0] != urls[0] || ice.URLs[1] != urls[1] {
		t.Fatalf("URLs mismatch: got %v", ice.URLs)
	}

	// Username is a future unix timestamp within TTL range.
	expiry, err := strconv.ParseInt(ice.Username, 10, 64)
	if err != nil {
		t.Fatalf("username is not a unix timestamp: %v", err)
	}
	earliest := before.Add(ttl).Unix()
	latest := after.Add(ttl).Unix()
	if expiry < earliest || expiry > latest {
		t.Fatalf("expiry %d not in expected range [%d, %d]", expiry, earliest, latest)
	}

	// Credential matches base64(HMAC-SHA1(secret, username)).
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(ice.Username))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if ice.Credential != want {
		t.Fatalf("credential mismatch:\n  got  %s\n  want %s", ice.Credential, want)
	}

	// Different timestamps produce different credentials.
	altUsername := strconv.FormatInt(expiry+3600, 10)
	altMac := hmac.New(sha1.New, []byte(secret))
	altMac.Write([]byte(altUsername))
	altCred := base64.StdEncoding.EncodeToString(altMac.Sum(nil))
	if altCred == ice.Credential {
		t.Fatal("different timestamps should produce different credentials")
	}
}
