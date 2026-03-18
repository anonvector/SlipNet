package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

const (
	encFormatVersion byte = 0x01
	gcmIVLength           = 12
	gcmTagLength          = 16
)

// decryptConfig decrypts an AES-256-GCM encrypted config blob.
// Format: [version(1)][iv(12)][ciphertext+tag(variable)]
func decryptConfig(data []byte) (string, error) {
	key := configKeyBytes()
	if key == nil {
		return "", fmt.Errorf("encrypted configs not supported in this build (no config key)")
	}

	if len(key) != 32 {
		return "", fmt.Errorf("invalid config key")
	}

	if len(data) == 0 || data[0] != encFormatVersion {
		return "", fmt.Errorf("unsupported encrypted format version")
	}

	minLength := 1 + gcmIVLength + gcmTagLength
	if len(data) < minLength {
		return "", fmt.Errorf("encrypted data too short")
	}

	iv := data[1 : 1+gcmIVLength]
	ciphertext := data[1+gcmIVLength:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed (wrong key or corrupted data)")
	}

	return string(plaintext), nil
}
