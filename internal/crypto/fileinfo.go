// SPDX-License-Identifier: MIT

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/hkdf"
)

// EncryptFileInfo encrypts file metadata using an AES-256-GCM key derived from the seed.
// Returns nonce || ciphertext (including GCM tag).
func EncryptFileInfo(seed, plaintext []byte) ([]byte, error) {
	key, err := deriveFileInfoKey(seed)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	// Wire format: nonce || ciphertext (includes tag).
	out := make([]byte, len(nonce)+len(ciphertext))
	copy(out, nonce)
	copy(out[len(nonce):], ciphertext)
	return out, nil
}

// DecryptFileInfo decrypts file metadata encrypted by EncryptFileInfo.
func DecryptFileInfo(seed, encrypted []byte) ([]byte, error) {
	key, err := deriveFileInfoKey(seed)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize+gcm.Overhead() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := encrypted[:nonceSize]
	ciphertext := encrypted[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// deriveFileInfoKey derives an AES-256 key from the seed for file-info encryption.
func deriveFileInfoKey(seed []byte) ([]byte, error) {
	prk := hkdf.Extract(sha256.New, seed, []byte("sp2p-file-info"))
	return hkdfExpand(prk, nil, "sp2p-v1-file-info-key", KeySize)
}
