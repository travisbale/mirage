package sqlite_test

import (
	"testing"

	"github.com/travisbale/mirage/internal/crypto/aes"
	"github.com/travisbale/mirage/internal/store/sqlite"
)

func openTestDB(t *testing.T) *sqlite.DB {
	t.Helper()
	db, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// testCipher returns a deterministic AES cipher for tests.
func testCipher() *aes.Cipher {
	c, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		panic(err)
	}
	return c
}
