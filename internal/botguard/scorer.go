package botguard

import (
	"log/slog"
	"strings"

	"github.com/travisbale/mirage/internal/aitm"
)

// BotGuardConfig holds runtime-adjustable settings for bot detection.
// BotGuardConfig holds runtime-adjustable settings for bot detection.
type BotGuardConfig struct {
	// Enabled controls whether bot detection is active.
	Enabled bool
	// TelemetryThreshold is the score threshold [0.0, 1.0] above which a
	// connection is considered a bot. Default is 0.6.
	TelemetryThreshold float64
}

// Scorer evaluates L2 (telemetry heuristic) signals into a BotVerdict.
// L1 (JA4 signature lookup) is handled upstream by BotGuardService.
type Scorer struct {
	Config BotGuardConfig
	Logger *slog.Logger
}

// ScoreConnection verdict logic:
//   - !Cfg.Enabled                → VerdictAllow
//   - telemetry score ≥ threshold → VerdictSpoof (L2 score)
//   - otherwise                   → VerdictAllow
func (s *Scorer) ScoreConnection(telemetry *aitm.BotTelemetry) aitm.BotVerdict {
	if !s.Config.Enabled {
		return aitm.VerdictAllow
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
	if renderer, ok := raw["webgl_renderer"].(string); ok {
		rendererLower := strings.ToLower(renderer)
		if strings.Contains(rendererLower, "swiftshader") ||
			strings.Contains(rendererLower, "llvmpipe") ||
			strings.Contains(rendererLower, "mesa") {
			score += 0.4
		}
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
	if tz, ok := raw["timezone"].(string); ok {
		tzOffset, _ := raw["timezone_offset"].(float64)
		if tz == "UTC" && tzOffset != 0 {
			score += 0.2
		}
	}

	if fonts, ok := raw["fonts_detected"].(float64); ok && fonts < 3 {
		score += 0.1 // minimal font set — headless doesn't install system fonts
	}

	if score > 1.0 {
		score = 1.0
	}
	return score
}
