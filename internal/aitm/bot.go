package aitm

import (
	"net/http"
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
	Phishlet         *PhishletDef
	PhishletCfg      *PhishletConfig
	Lure             *Lure
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

// botScorer is the interface implemented by botguard.Scorer.
// It combines L1 (JA4 hash lookup) and L2 (telemetry heuristic) signals
// into a single verdict per connection.
type botScorer interface {
	ScoreConnection(ja4 string, telemetry *BotTelemetry) BotVerdict
}

// BotGuardService evaluates connections for bot/scanner signatures.
type BotGuardService struct {
	Scorer botScorer
	Store  botTelemetryStore
	Bus    EventBus
}

func (s *BotGuardService) Evaluate(ja4 string, telemetry *BotTelemetry) BotVerdict {
	return s.Scorer.ScoreConnection(ja4, telemetry)
}

// ScoreSession loads stored telemetry for sessionID and returns a [0.0, 1.0]
// bot probability score. Returns 1.0 if any telemetry record scores as non-allow.
func (s *BotGuardService) ScoreSession(sessionID string) float64 {
	records, err := s.Store.GetBotTelemetry(sessionID)
	if err != nil || len(records) == 0 {
		return 0.0
	}
	for _, record := range records {
		if s.Scorer.ScoreConnection("", record) != VerdictAllow {
			return 1.0
		}
	}
	return 0.0
}
