package sqlite_test

import (
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/store/sqlite"
)

func TestWithTx_Rollback(t *testing.T) {
	db := openTestDB(t)

	// A failed transaction should not persist any work.
	err := db.WithTx(func(tx *sql.Tx) error {
		_, _ = tx.Exec(`INSERT INTO sessions (id, phishlet, started_at) VALUES (?,?,?)`, "tx-sess", "p", time.Now().Unix())
		return fmt.Errorf("intentional failure")
	})
	if err == nil {
		t.Fatal("expected error from WithTx, got nil")
	}

	// The session should not exist because the transaction was rolled back.
	s := sqlite.NewSessionStore(db, testCipher())
	if _, err := s.GetSession("tx-sess"); !errors.Is(err, aitm.ErrNotFound) {
		t.Errorf("rolled-back session should not exist, got %v", err)
	}
}
