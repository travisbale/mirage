package request

import (
	"net/http"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
)

// botEvaluator evaluates a JA4 hash against the bot signature database.
type botEvaluator interface {
	Evaluate(ja4 string, telemetry *aitm.BotTelemetry) aitm.BotVerdict
}

// BotGuardCheck short-circuits to the spoofer when a connection's JA4 hash
// matches a known-bad signature.
type BotGuardCheck struct {
	Service botEvaluator
	Spoof   spoofer
}

func (h *BotGuardCheck) Name() string { return "BotGuardCheck" }

func (h *BotGuardCheck) Handle(ctx *aitm.ProxyContext, req *http.Request) error {
	if ctx.JA4Hash == "" {
		return nil
	}

	ctx.BotVerdict = h.Service.Evaluate(ctx.JA4Hash, nil)
	if ctx.BotVerdict == aitm.VerdictSpoof {
		h.Spoof.ServeHTTP(ctx.ResponseWriter, req)
		return proxy.ErrShortCircuit
	}
	if ctx.BotVerdict == aitm.VerdictBlock {
		http.Error(ctx.ResponseWriter, "Not Found", http.StatusNotFound)
		return proxy.ErrShortCircuit
	}

	return nil
}

var _ proxy.RequestHandler = (*BotGuardCheck)(nil)
