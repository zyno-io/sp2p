// SPDX-License-Identifier: MIT

package crypto

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

const (
	// SeedBits is the bit length of the encryption seed.
	SeedBits = 128
	// SeedBytes is the byte length of the encryption seed.
	SeedBytes = SeedBits / 8
)

// Base62 alphabet for seed encoding.
const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

var base62Big = big.NewInt(62)

// GenerateSeed generates a cryptographically random 128-bit seed and returns it base62-encoded.
func GenerateSeed() (encoded string, raw []byte, err error) {
	raw = make([]byte, SeedBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generating seed: %w", err)
	}
	encoded = base62Encode(raw)
	return encoded, raw, nil
}

// DecodeSeed decodes a base62-encoded seed back to raw bytes.
func DecodeSeed(encoded string) ([]byte, error) {
	raw, err := base62Decode(encoded)
	if err != nil {
		return nil, fmt.Errorf("decoding seed: %w", err)
	}
	if len(raw) > SeedBytes {
		return nil, fmt.Errorf("decoded seed too large: %d bytes, expected at most %d", len(raw), SeedBytes)
	}
	if len(raw) < SeedBytes {
		// Pad with leading zeros if needed.
		padded := make([]byte, SeedBytes)
		copy(padded[SeedBytes-len(raw):], raw)
		raw = padded
	}
	return raw, nil
}

func base62Encode(data []byte) string {
	n := new(big.Int).SetBytes(data)
	if n.Sign() == 0 {
		return "0"
	}

	var result []byte
	zero := big.NewInt(0)
	mod := new(big.Int)

	for n.Cmp(zero) > 0 {
		n.DivMod(n, base62Big, mod)
		result = append(result, base62[mod.Int64()])
	}

	// Reverse.
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return string(result)
}

func base62Decode(s string) ([]byte, error) {
	n := big.NewInt(0)
	for _, c := range s {
		idx := strings.IndexRune(base62, c)
		if idx < 0 {
			return nil, fmt.Errorf("invalid base62 character: %c", c)
		}
		n.Mul(n, base62Big)
		n.Add(n, big.NewInt(int64(idx)))
	}
	return n.Bytes(), nil
}

// ParseCode splits a transfer code into sessionID and seed.
func ParseCode(code string) (sessionID, seed string, err error) {
	parts := strings.SplitN(code, "-", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid transfer code format: expected SESSION_ID-SEED")
	}
	return parts[0], parts[1], nil
}

// FormatCode creates a transfer code from sessionID and seed.
func FormatCode(sessionID, seed string) string {
	return sessionID + "-" + seed
}
