// Package crypto provides encryption key management for mirage.
package crypto

import (
	"crypto/rand"
	"fmt"
	"os"
)

// LoadOrGenerateKey reads a 32-byte AES-256 key from path. If the file does
// not exist, a new random key is generated and written with mode 0600.
func LoadOrGenerateKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err == nil {
		if len(key) != 32 {
			return nil, fmt.Errorf("encryption key at %s has invalid length %d (expected 32)", path, len(key))
		}
		return key, nil
	}

	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading encryption key: %w", err)
	}

	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating encryption key: %w", err)
	}

	if err := os.WriteFile(path, key, 0600); err != nil {
		return nil, fmt.Errorf("writing encryption key: %w", err)
	}

	return key, nil
}
