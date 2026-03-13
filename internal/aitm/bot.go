package aitm

import "time"

// BotStore is the persistence interface required by BotGuardService.
type BotStore interface {
	StoreBotTelemetry(t *BotTelemetry) error
	GetBotTelemetry(sessionID string) ([]*BotTelemetry, error)
	DeleteBotTelemetry(sessionID string) error
}

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
	ClientIP    string
	JA4Hash     string
	BotVerdict  BotVerdict
	Phishlet    *PhishletDef
	PhishletCfg *PhishletConfig
	Lure        *Lure
	Session     *Session
	IsNewSession bool
}

// BotScorer is the interface implemented by botguard.Scorer.
// It combines L1 (JA4 hash lookup) and L2 (telemetry heuristic) signals
// into a single verdict per connection.
type BotScorer interface {
	ScoreConnection(ja4 string, telemetry *BotTelemetry) BotVerdict
}

// BotGuardService evaluates connections for bot/scanner signatures.
type BotGuardService struct {
	scorer BotScorer
	store  BotStore
	bus    EventBus
}

func NewBotGuardService(scorer BotScorer, store BotStore, bus EventBus) *BotGuardService {
	return &BotGuardService{scorer: scorer, store: store, bus: bus}
}

// Evaluate delegates to the injected BotScorer.
func (s *BotGuardService) Evaluate(ja4 string, telemetry *BotTelemetry) BotVerdict {
	return s.scorer.ScoreConnection(ja4, telemetry)
}
