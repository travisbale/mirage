package request

import (
	"net/http"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
)

// TelemetryScorer returns the accumulated bot score for a session.
type TelemetryScorer interface {
	ScoreSession(sessionID string) float64
}

// TelemetryScoreCheck re-evaluates sessions that have accumulated telemetry data.
type TelemetryScoreCheck struct {
	Scorer    TelemetryScorer
	Spoof     spoofer
	Threshold float64
}

func (h *TelemetryScoreCheck) Name() string { return "TelemetryScoreCheck" }

func (h *TelemetryScoreCheck) Handle(ctx *aitm.ProxyContext, req *http.Request) error {
	if ctx.Session == nil || ctx.BotVerdict != aitm.VerdictAllow {
		return nil
	}
	botScore := h.Scorer.ScoreSession(ctx.Session.ID)
	ctx.Session.BotScore = botScore
	if botScore > h.Threshold {
		ctx.BotVerdict = aitm.VerdictSpoof
		h.Spoof.ServeWithTarget(ctx.ResponseWriter, req, contextSpoofURL(ctx))
		return proxy.ErrShortCircuit
	}
	return nil
}

var _ proxy.RequestHandler = (*TelemetryScoreCheck)(nil)
