package botguard_test

import (
	"log/slog"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/botguard"
)

func TestScorer_DisabledAlwaysAllows(t *testing.T) {
	scorer := &botguard.Scorer{Config: botguard.BotGuardConfig{Enabled: false}, Logger: slog.Default()}
	verdict := scorer.ScoreConnection(nil)
	if verdict != aitm.VerdictAllow {
		t.Errorf("expected VerdictAllow when disabled, got %v", verdict)
	}
}

func TestScorer_HighTelemetryScoreReturnsVerdictSpoof(t *testing.T) {
	scorer := &botguard.Scorer{Config: botguard.BotGuardConfig{Enabled: true, TelemetryThreshold: 0.6}, Logger: slog.Default()}
	// SwiftShader renderer + 0 mouse moves + pixel_ratio 1.0 + device_memory 0 → score > 0.6
	telem := &aitm.BotTelemetry{Raw: map[string]any{
		"webgl_renderer":   "ANGLE (SwiftShader)",
		"mouse_move_count": float64(0),
		"pixel_ratio":      float64(1.0),
		"device_memory":    float64(0),
		"fonts_detected":   float64(1),
	}}
	verdict := scorer.ScoreConnection(telem)
	if verdict != aitm.VerdictSpoof {
		t.Errorf("expected VerdictSpoof for high telemetry score, got %v", verdict)
	}
}

func TestScorer_NilTelemetryAllows(t *testing.T) {
	scorer := &botguard.Scorer{Config: botguard.BotGuardConfig{Enabled: true, TelemetryThreshold: 0.6}, Logger: slog.Default()}
	verdict := scorer.ScoreConnection(nil)
	if verdict != aitm.VerdictAllow {
		t.Errorf("expected VerdictAllow for nil telemetry, got %v", verdict)
	}
}

func TestScorer_EmptyTelemetryAllows(t *testing.T) {
	scorer := &botguard.Scorer{Config: botguard.BotGuardConfig{Enabled: true, TelemetryThreshold: 0.6}, Logger: slog.Default()}
	telem := &aitm.BotTelemetry{Raw: map[string]any{}}
	verdict := scorer.ScoreConnection(telem)
	if verdict != aitm.VerdictAllow {
		t.Errorf("expected VerdictAllow for empty telemetry, got %v", verdict)
	}
}

func TestScorer_BelowThresholdAllows(t *testing.T) {
	scorer := &botguard.Scorer{Config: botguard.BotGuardConfig{Enabled: true, TelemetryThreshold: 0.6}, Logger: slog.Default()}
	// Only SwiftShader (0.4) → below 0.6 threshold.
	telem := &aitm.BotTelemetry{Raw: map[string]any{
		"webgl_renderer": "ANGLE (SwiftShader)",
	}}
	verdict := scorer.ScoreConnection(telem)
	if verdict != aitm.VerdictAllow {
		t.Errorf("expected VerdictAllow for score below threshold, got %v", verdict)
	}
}

func TestScorer_ExactThresholdSpoofs(t *testing.T) {
	scorer := &botguard.Scorer{Config: botguard.BotGuardConfig{Enabled: true, TelemetryThreshold: 0.6}, Logger: slog.Default()}
	// SwiftShader (0.4) + no plugins (0.2) = 0.6 exactly.
	telem := &aitm.BotTelemetry{Raw: map[string]any{
		"webgl_renderer": "SwiftShader",
		"plugins_hash":   "",
	}}
	verdict := scorer.ScoreConnection(telem)
	if verdict != aitm.VerdictSpoof {
		t.Errorf("expected VerdictSpoof at exact threshold, got %v", verdict)
	}
}

func TestScorer_ScoreCapsAtOne(t *testing.T) {
	scorer := &botguard.Scorer{Config: botguard.BotGuardConfig{Enabled: true, TelemetryThreshold: 0.6}, Logger: slog.Default()}
	// All signals: 0.4 + 0.2 + 0.15 + 0.1 + 0.15 + 0.2 + 0.1 = 1.3 → capped at 1.0.
	telem := &aitm.BotTelemetry{Raw: map[string]any{
		"webgl_renderer":   "SwiftShader",
		"plugins_hash":     "",
		"mouse_move_count": float64(0),
		"pixel_ratio":      float64(1.0),
		"device_memory":    float64(0),
		"timezone":         "UTC",
		"timezone_offset":  float64(5),
		"fonts_detected":   float64(1),
	}}
	verdict := scorer.ScoreConnection(telem)
	if verdict != aitm.VerdictSpoof {
		t.Errorf("expected VerdictSpoof for maxed signals, got %v", verdict)
	}
}
