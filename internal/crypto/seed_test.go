// SPDX-License-Identifier: MIT

package crypto

import (
	"testing"
)

func TestGenerateAndDecodeSeed(t *testing.T) {
	encoded, raw, err := GenerateSeed()
	if err != nil {
		t.Fatal(err)
	}

	if len(raw) != SeedBytes {
		t.Fatalf("expected %d raw bytes, got %d", SeedBytes, len(raw))
	}

	if len(encoded) == 0 {
		t.Fatal("encoded seed is empty")
	}

	decoded, err := DecodeSeed(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if len(decoded) != SeedBytes {
		t.Fatalf("expected %d decoded bytes, got %d", SeedBytes, len(decoded))
	}

	for i := range raw {
		if raw[i] != decoded[i] {
			t.Fatalf("mismatch at byte %d: %02x != %02x", i, raw[i], decoded[i])
		}
	}
}

func TestBase62RoundTrip(t *testing.T) {
	tests := [][]byte{
		{0},
		{0xFF},
		{0x01, 0x02, 0x03},
		{0xFF, 0xFF, 0xFF, 0xFF},
	}

	for _, data := range tests {
		encoded := base62Encode(data)
		decoded, err := base62Decode(encoded)
		if err != nil {
			t.Fatalf("decode error for %x: %v", data, err)
		}
		// Compare numerical values (leading zeros may be stripped).
		// Re-encode to compare.
		reEncoded := base62Encode(decoded)
		if encoded != reEncoded {
			t.Fatalf("round-trip failed: %x -> %s -> %x -> %s", data, encoded, decoded, reEncoded)
		}
	}
}

func TestParseCode(t *testing.T) {
	sessionID, seed, err := ParseCode("abc12345-RF6k7wc5do8cAMuAHaaEEFJy")
	if err != nil {
		t.Fatal(err)
	}
	if sessionID != "abc12345" {
		t.Fatalf("expected session ID 'abc12345', got '%s'", sessionID)
	}
	if seed != "RF6k7wc5do8cAMuAHaaEEFJy" {
		t.Fatalf("expected seed 'RF6k7wc5do8cAMuAHaaEEFJy', got '%s'", seed)
	}
}

func TestParseCodeInvalid(t *testing.T) {
	tests := []string{
		"",
		"noseparator",
		"-nosession",
		"noseed-",
	}
	for _, code := range tests {
		_, _, err := ParseCode(code)
		if err == nil {
			t.Fatalf("expected error for code %q", code)
		}
	}
}

func TestFormatCode(t *testing.T) {
	code := FormatCode("abc12345", "RF6k7wc5do8cAMuAHaaEEFJy")
	if code != "abc12345-RF6k7wc5do8cAMuAHaaEEFJy" {
		t.Fatalf("unexpected code: %s", code)
	}
}

func TestDecodeSeedOversized(t *testing.T) {
	// Encode a 17-byte value (exceeds SeedBytes=16) in base62.
	oversized := make([]byte, SeedBytes+1)
	for i := range oversized {
		oversized[i] = 0xFF
	}
	encoded := base62Encode(oversized)

	_, err := DecodeSeed(encoded)
	if err == nil {
		t.Fatal("expected error for oversized seed")
	}
	if !testing.Verbose() {
		t.Logf("got expected error: %v", err)
	}
}
