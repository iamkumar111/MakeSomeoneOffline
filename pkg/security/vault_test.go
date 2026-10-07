package security

import (
	"testing"
)

func TestVaultRejectsDefaultKey(t *testing.T) {
	if _, err := NewVault(""); err == nil {
		t.Fatal("empty key silently used a known default")
	}
}

func TestVaultEncryptionDecryption(t *testing.T) {
	vault, err := NewVault("my-secure-cluster-passphrase-2026")
	if err != nil {
		t.Fatalf("failed to initialize vault: %v", err)
	}

	secret := "SuperSecretRouterPassword123!"
	encrypted, err := vault.Encrypt([]byte(secret))
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	if encrypted == secret {
		t.Fatal("ciphertext should not match plaintext")
	}

	decrypted, err := vault.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if string(decrypted) != secret {
		t.Errorf("expected %q, got %q", secret, string(decrypted))
	}
}

func TestRedactMapAndSecrets(t *testing.T) {
	masked := RedactSecret("password123")
	if masked == "password123" {
		t.Error("expected secret to be masked")
	}

	data := map[string]interface{}{
		"host":     "192.168.1.1",
		"username": "admin",
		"password": "RouterPassword!",
		"api_key":  "secret-token-key-999",
	}

	cleaned := RedactMap(data)
	if cleaned["password"] != "[REDACTED]" {
		t.Errorf("expected password to be redacted, got %v", cleaned["password"])
	}
	if cleaned["api_key"] != "[REDACTED]" {
		t.Errorf("expected api_key to be redacted, got %v", cleaned["api_key"])
	}
	if cleaned["username"] != "admin" {
		t.Errorf("expected username to be preserved, got %v", cleaned["username"])
	}
}
