// Package sqlite implements the aitm storage interfaces using SQLite.
package sqlite

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/travisbale/mirage/internal/store"
	_ "modernc.org/sqlite"
)

// Re-export shared sentinels so callers only need to import one package.
var (
	ErrNotFound     = store.ErrNotFound
	ErrConflict     = store.ErrConflict
	ErrInvalidFilter = store.ErrInvalidFilter
)

// DB is the shared SQLite connection. Open once; pass to each domain store constructor.
type DB struct {
	db *sql.DB
}

// Open opens (or creates) the SQLite database at path, enables WAL mode and
// foreign key enforcement, then runs all pending migrations.
// Pass ":memory:" for an ephemeral database suitable for tests.
func Open(path string) (*DB, error) {
	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("sqlite.Open: %w", err)
	}

	// A single connection avoids "database is locked" errors common with SQLite.
	sqlDB.SetMaxOpenConns(1)

	if _, err := sqlDB.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		return nil, fmt.Errorf("sqlite.Open: setting WAL mode: %w", err)
	}
	if _, err := sqlDB.Exec(`PRAGMA foreign_keys=ON`); err != nil {
		return nil, fmt.Errorf("sqlite.Open: enabling foreign keys: %w", err)
	}

	db := &DB{db: sqlDB}
	if err := runMigrations(db.db); err != nil {
		return nil, fmt.Errorf("sqlite.Open: running migrations: %w", err)
	}
	return db, nil
}

// Close releases the underlying database connection.
func (d *DB) Close() error { return d.db.Close() }

// WithTx executes fn inside a transaction. If fn returns an error the transaction
// is rolled back; otherwise it is committed.
func (d *DB) WithTx(fn func(*sql.Tx) error) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// scanner is satisfied by both *sql.Row and *sql.Rows, allowing scan helpers
// to work with both QueryRow and the rows returned by Query.
type scanner interface {
	Scan(dest ...any) error
}

// requireOneRow returns ErrNotFound if the statement affected zero rows.
func requireOneRow(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// isConflict returns true for SQLite UNIQUE constraint violation errors.
func isConflict(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}
