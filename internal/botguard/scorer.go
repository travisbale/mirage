package botguard

import (
	"log/slog"
	"strings"

	"github.com/travisbale/mirage/internal/aitm"
)

// BotGuardConfig holds runtime-adjustable settings for bot detection.
type BotGuardConfig struct {
	Enabled            bool
	TelemetryThreshold float64 // [0.0, 1.0]; default 0.6
	GlobalSpoofURL     string
}

// signatureFinder is the minimal interface the Scorer needs for L1 checks.
// Callers satisfy it implicitly.
type signatureFinder interface {
	LookupBotSignature(ja4Hash string) (aitm.BotSignature, error)
}

// Scorer combines L1 (JA4 signature lookup) and L2 (telemetry heuristic) signals
// into a BotVerdict. It implicitly satisfies aitm.BotScorer.
type Scorer struct {
	Config          BotGuardConfig
	SignatureFinder signatureFinder
	Logger          *slog.Logger
}

// ScoreConnection verdict logic:
//   - !Cfg.Enabled                → VerdictAllow
//   - ja4 in SigDB                → VerdictSpoof (L1 match)
//   - telemetry score ≥ threshold → VerdictSpoof (L2 score)
//   - otherwise                   → VerdictAllow
func (s *Scorer) ScoreConnection(ja4 string, telemetry *aitm.BotTelemetry) aitm.BotVerdict {
	if !s.Config.Enabled {
		return aitm.VerdictAllow
	}
	if ja4 != "" {
		if sig, err := s.SignatureFinder.LookupBotSignature(ja4); err == nil {
			s.Logger.Info("botguard: L1 match", "ja4", ja4, "description", sig.Description)
			return aitm.VerdictSpoof
		}
	}
	if telemetry != nil && s.scoreTelemetry(telemetry) >= s.Config.TelemetryThreshold {
		return aitm.VerdictSpoof
	}
	return aitm.VerdictAllow
}

// scoreTelemetry computes a [0.0, 1.0] bot probability score from the
// telemetry blob. Each signal contributes an additive weight; the total
// is clamped to 1.0. Threshold is configurable in BotGuardConfig (default 0.6).
func (s *Scorer) scoreTelemetry(telemetry *aitm.BotTelemetry) float64 {
	raw := telemetry.Raw
	score := 0.0

	// SwiftShader/llvmpipe/Mesa are software renderers used by headless Chrome.
	renderer, _ := raw["webgl_renderer"].(string)
	rendererLower := strings.ToLower(renderer)
	if strings.Contains(rendererLower, "swiftshader") ||
		strings.Contains(rendererLower, "llvmpipe") ||
		strings.Contains(rendererLower, "mesa") {
		score += 0.4
	}

	if pluginsHash, ok := raw["plugins_hash"].(string); ok && pluginsHash == "" {
		score += 0.2 // no browser plugins — typical of headless
	}

	if moves, ok := raw["mouse_move_count"].(float64); ok && moves == 0 {
		score += 0.15 // no mouse activity
	}

	// Headless Chrome defaults to devicePixelRatio=1.
	if ratio, ok := raw["pixel_ratio"].(float64); ok && ratio == 1.0 {
		score += 0.1
	}

	if mem, ok := raw["device_memory"].(float64); ok && mem == 0 {
		score += 0.15 // deviceMemory=0 in headless
	}

	// UTC timezone with non-zero offset indicates a spoofed/misconfigured environment.
	tz, _ := raw["timezone"].(string)
	offset, _ := raw["timezone_offset"].(float64)
	if tz == "UTC" && offset != 0 {
		score += 0.2
	}

	if fonts, ok := raw["fonts_detected"].(float64); ok && fonts < 3 {
		score += 0.1 // minimal font set — headless doesn't install system fonts
	}

	if score > 1.0 {
		score = 1.0
	}
	return score
}
