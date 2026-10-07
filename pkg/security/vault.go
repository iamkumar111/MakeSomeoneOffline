package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
)

// Vault handles authenticated encryption at rest (AES-256-GCM) for sensitive credentials.
type Vault struct {
	mu     sync.RWMutex
	aesGCM cipher.AEAD
}

// NewVault initializes an AES-256-GCM encryption vault from a passphrase or master key.
func NewVault(passphrase string) (*Vault, error) {
	if passphrase == "" {
		return nil, fmt.Errorf("vault requires an explicit secret key; no default encryption key is permitted")
	}

	// Derive 32-byte key using SHA-256
	key := sha256.Sum256([]byte(passphrase))

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM AEAD: %w", err)
	}

	return &Vault{
		aesGCM: aesGCM,
	}, nil
}

// Encrypt encrypts plaintext bytes with a fresh random nonce and returns base64 ciphertext.
func (v *Vault) Encrypt(plaintext []byte) (string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	nonce := make([]byte, v.aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := v.aesGCM.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decodes base64 ciphertext, extracts nonce, and authenticates/decrypts payload.
func (v *Vault) Decrypt(encodedCiphertext string) ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	data, err := base64.StdEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		return nil, fmt.Errorf("base64 decode error: %w", err)
	}

	nonceSize := v.aesGCM.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := v.aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption/authentication failed: %w", err)
	}

	return plaintext, nil
}

// RedactSecret masks sensitive strings for logs and API responses.
func RedactSecret(secret string) string {
	if len(secret) <= 4 {
		return "••••"
	}
	return secret[:2] + strings.Repeat("•", len(secret)-4) + secret[len(secret)-2:]
}

// RedactMap recursively replaces sensitive keys in maps for safe logging and audit.
func RedactMap(data map[string]interface{}) map[string]interface{} {
	clean := make(map[string]interface{})
	sensitiveKeys := map[string]bool{
		"password": true, "secret": true, "token": true, "api_key": true,
		"private_key": true, "credential": true, "auth": true,
	}

	for k, v := range data {
		lowerK := strings.ToLower(k)
		if sensitiveKeys[lowerK] {
			clean[k] = "[REDACTED]"
			continue
		}

		if subMap, ok := v.(map[string]interface{}); ok {
			clean[k] = RedactMap(subMap)
		} else {
			clean[k] = v
		}
	}
	return clean
}

// MaskCredentialsInJSON redacts sensitive fields in raw JSON before logging.
func MaskCredentialsInJSON(rawJSON []byte) string {
	var m map[string]interface{}
	if err := json.Unmarshal(rawJSON, &m); err != nil {
		return string(rawJSON)
	}
	cleaned := RedactMap(m)
	out, _ := json.Marshal(cleaned)
	return string(out)
}
