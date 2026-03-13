package botguard

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
)

// signatureFile is the JSON schema for the on-disk JA4 signature database.
//
// Example:
//
//	{
//	  "updated_at": "2025-01-01T00:00:00Z",
//	  "signatures": [
//	    {"ja4_hash": "t13d1516h2_8daaf6152771_b0da82dd1658", "description": "zgrab2 TLS scanner"}
//	  ]
//	}
type signatureFile struct {
	UpdatedAt  time.Time           `json:"updated_at"`
	Signatures []aitm.BotSignature `json:"signatures"`
}

// JA4SignatureDB is a thread-safe in-memory database of known-bad JA4 hashes.
// It loads from a JSON file on disk and hot-reloads when EventPhishletReloaded fires.
type JA4SignatureDB struct {
	path   string
	logger *slog.Logger

	mu   sync.RWMutex
	sigs map[string]aitm.BotSignature // key: ja4_hash
}

// NewJA4SignatureDB constructs the database and loads the file immediately.
// Returns an error if the file exists but cannot be parsed.
// If path does not exist, the DB starts empty (warn-only, not a hard error).
func NewJA4SignatureDB(path string, bus aitm.EventBus, logger *slog.Logger) (*JA4SignatureDB, error) {
	db := &JA4SignatureDB{
		path:   path,
		sigs:   make(map[string]aitm.BotSignature),
		logger: logger,
	}
	if err := db.load(); err != nil {
		if os.IsNotExist(err) {
			logger.Warn("ja4db: signature file not found, starting empty", "path", path)
		} else {
			return nil, fmt.Errorf("ja4db: initial load: %w", err)
		}
	}

	// Subscribe to reload events and hot-reload the file when they arrive.
	reloadCh := bus.Subscribe(aitm.EventPhishletReloaded)
	if reloadCh != nil {
		go func() {
			for range reloadCh {
				if err := db.load(); err != nil {
					logger.Error("ja4db: reload failed", "error", err)
				} else {
					logger.Info("ja4db: reloaded", "path", path)
				}
			}
		}()
	}

	return db, nil
}

// Lookup returns the BotSignature for ja4Hash, and true if found.
// Returns (zero value, false) if the hash is not in the database.
func (db *JA4SignatureDB) Lookup(ja4Hash string) (aitm.BotSignature, bool) {
	db.mu.RLock()
	sig, ok := db.sigs[ja4Hash]
	db.mu.RUnlock()
	return sig, ok
}

// Add inserts or updates a signature at runtime.
// The change is not persisted to disk — call Save for that.
func (db *JA4SignatureDB) Add(sig aitm.BotSignature) {
	db.mu.Lock()
	db.sigs[sig.JA4Hash] = sig
	db.mu.Unlock()
}

// Remove deletes a signature by hash. Returns false if not found.
func (db *JA4SignatureDB) Remove(ja4Hash string) bool {
	db.mu.Lock()
	_, ok := db.sigs[ja4Hash]
	delete(db.sigs, ja4Hash)
	db.mu.Unlock()
	return ok
}

// List returns all signatures as a slice (unsorted).
func (db *JA4SignatureDB) List() []aitm.BotSignature {
	db.mu.RLock()
	defer db.mu.RUnlock()
	out := make([]aitm.BotSignature, 0, len(db.sigs))
	for _, sig := range db.sigs {
		out = append(out, sig)
	}
	return out
}

// Count returns the number of signatures currently loaded.
func (db *JA4SignatureDB) Count() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.sigs)
}

// load reads and parses the JSON file, replacing the in-memory map atomically.
func (db *JA4SignatureDB) load() error {
	data, err := os.ReadFile(db.path)
	if err != nil {
		return err
	}
	var f signatureFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("parsing signature file: %w", err)
	}
	fresh := make(map[string]aitm.BotSignature, len(f.Signatures))
	for _, sig := range f.Signatures {
		fresh[sig.JA4Hash] = sig
	}
	db.mu.Lock()
	db.sigs = fresh
	db.mu.Unlock()
	db.logger.Info("ja4db: loaded", "count", len(fresh))
	return nil
}

// Save writes the current in-memory signatures back to the JSON file.
func (db *JA4SignatureDB) Save() error {
	db.mu.RLock()
	sigs := make([]aitm.BotSignature, 0, len(db.sigs))
	for _, sig := range db.sigs {
		sigs = append(sigs, sig)
	}
	db.mu.RUnlock()

	f := signatureFile{
		UpdatedAt:  time.Now().UTC(),
		Signatures: sigs,
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(db.path, data, 0644)
}
