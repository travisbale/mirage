package crypto_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/travisbale/mirage/internal/crypto"
)

func TestLoadOrGenerateKey_GeneratesAndLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "encryption.key")

	key1, err := crypto.LoadOrGenerateKey(path)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if len(key1) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key1))
	}

	// Verify file permissions.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected mode 0600, got %o", info.Mode().Perm())
	}

	// Second call should return the same key.
	key2, err := crypto.LoadOrGenerateKey(path)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if string(key1) != string(key2) {
		t.Error("expected same key on second load")
	}
}

func TestLoadOrGenerateKey_InvalidLength(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.key")
	if err := os.WriteFile(path, []byte("short"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := crypto.LoadOrGenerateKey(path)
	if err == nil {
		t.Error("expected error for invalid key length")
	}
}
