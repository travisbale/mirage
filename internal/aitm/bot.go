package aitm

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

type BotVerdict int

const (
	VerdictAllow BotVerdict = iota
	VerdictSpoof
	VerdictBlock
)

type BotTelemetry struct {
	ID          string
	SessionID   string
	CollectedAt time.Time
	Raw         map[string]any
}

type BotSignature struct {
	JA4Hash     string
	Description string
	AddedAt     time.Time
}

// ProxyContext is the per-connection state bag threaded through the request pipeline.
// Allocated once per connection; must not be shared across goroutines.
type ProxyContext struct {
	ClientIP         string
	JA4Hash          string
	ClientHelloBytes []byte // raw TLS ClientHello record, set before pipeline runs
	BotVerdict       BotVerdict
	Phishlet    *PhishletDef
	Deployment  *PhishletDeployment
	Lure        *Lure
	Session          *Session
	IsNewSession     bool

	// ResponseWriter is set by the CONNECT handler so short-circuiting handlers
	// can write directly to the client without going upstream.
	ResponseWriter http.ResponseWriter

	// RequestID is a random hex string assigned at connection time for log correlation.
	RequestID string
}

type botTelemetryStore interface {
	StoreBotTelemetry(t *BotTelemetry) error
	GetBotTelemetry(sessionID string) ([]*BotTelemetry, error)
	DeleteBotTelemetry(sessionID string) error
}

type botSignatureStore interface {
	CreateBotSignature(sig BotSignature) error
	DeleteBotSignature(ja4Hash string) (bool, error)
	ListBotSignatures() ([]BotSignature, error)
}

// botScorer is the interface implemented by botguard.Scorer.
// It handles L2 (telemetry heuristic) scoring only.
type botScorer interface {
	ScoreConnection(telemetry *BotTelemetry) BotVerdict
}

// BotGuardService evaluates connections for bot/scanner signatures.
// L1 (JA4 signature lookup) is performed in-memory via signatures sync.Map.
// L2 (telemetry heuristic) is delegated to Scorer.
type BotGuardService struct {
	Scorer         botScorer
	Store          botTelemetryStore
	SignatureStore  botSignatureStore
	Bus            EventBus
	signatures     sync.Map // ja4hash → struct{}
}

// LoadSignaturesFromDB populates the in-memory signature set from the database.
// Call once at startup before serving requests.
func (s *BotGuardService) LoadSignaturesFromDB() error {
	sigs, err := s.SignatureStore.ListBotSignatures()
	if err != nil {
		return fmt.Errorf("loading bot signatures: %w", err)
	}
	for _, sig := range sigs {
		s.signatures.Store(sig.JA4Hash, struct{}{})
	}
	return nil
}

// AddSignature persists a new bot signature and adds it to the in-memory set.
func (s *BotGuardService) AddSignature(sig BotSignature) error {
	if err := s.SignatureStore.CreateBotSignature(sig); err != nil {
		return err
	}
	s.signatures.Store(sig.JA4Hash, struct{}{})
	return nil
}

// RemoveSignature deletes a bot signature from the database and in-memory set.
func (s *BotGuardService) RemoveSignature(ja4Hash string) (bool, error) {
	found, err := s.SignatureStore.DeleteBotSignature(ja4Hash)
	if err != nil {
		return false, err
	}
	if found {
		s.signatures.Delete(ja4Hash)
	}
	return found, nil
}

// ListSignatures returns all persisted bot signatures.
func (s *BotGuardService) ListSignatures() ([]BotSignature, error) {
	return s.SignatureStore.ListBotSignatures()
}

// Evaluate checks L1 (in-memory JA4 signature) then L2 (telemetry heuristic).
func (s *BotGuardService) Evaluate(ja4 string, telemetry *BotTelemetry) BotVerdict {
	if _, ok := s.signatures.Load(ja4); ok {
		return VerdictSpoof
	}
	return s.Scorer.ScoreConnection(telemetry)
}

// ScoreSession loads stored telemetry for sessionID and returns a [0.0, 1.0]
// bot probability score. Returns 1.0 if any telemetry record scores as non-allow.
func (s *BotGuardService) ScoreSession(sessionID string) float64 {
	records, err := s.Store.GetBotTelemetry(sessionID)
	if err != nil || len(records) == 0 {
		return 0.0
	}
	for _, record := range records {
		if s.Scorer.ScoreConnection(record) != VerdictAllow {
			return 1.0
		}
	}
	return 0.0
}
