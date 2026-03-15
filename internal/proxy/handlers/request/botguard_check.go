package request

import (
	"net/http"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
)

// BotEvaluator evaluates a JA4 hash against the bot signature database.
type BotEvaluator interface {
	Evaluate(ja4 string, telemetry *aitm.BotTelemetry) aitm.BotVerdict
}

// BotGuardCheck short-circuits to the spoof proxy when a connection's JA4 hash
// matches a known-bad signature.
type BotGuardCheck struct {
	Service BotEvaluator
	Spoof   proxy.Spoofer
}

func (h *BotGuardCheck) Name() string { return "BotGuardCheck" }

func (h *BotGuardCheck) Handle(ctx *aitm.ProxyContext, req *http.Request) error {
	if ctx.JA4Hash == "" {
		return nil
	}
	verdict := h.Service.Evaluate(ctx.JA4Hash, nil)
	ctx.BotVerdict = verdict
	if verdict == aitm.VerdictSpoof {
		h.Spoof.ServeHTTP(ctx.ResponseWriter, req)
		return proxy.ErrShortCircuit
	}
	if verdict == aitm.VerdictBlock {
		http.Error(ctx.ResponseWriter, "Not Found", http.StatusNotFound)
		return proxy.ErrShortCircuit
	}
	return nil
}

var _ proxy.RequestHandler = (*BotGuardCheck)(nil)
