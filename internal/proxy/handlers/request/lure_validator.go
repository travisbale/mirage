package request

import (
	"net/http"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
)

// LureValidator rejects connections arriving via a paused or UA-filtered lure.
type LureValidator struct {
	Spoof proxy.Spoofer
}

func (h *LureValidator) Name() string { return "LureValidator" }

func (h *LureValidator) Handle(ctx *aitm.ProxyContext, req *http.Request) error {
	if ctx.Lure == nil {
		return nil
	}
	if ctx.Lure.IsPaused() {
		h.Spoof.ServeHTTP(ctx.ResponseWriter, req)
		return proxy.ErrShortCircuit
	}
	if !ctx.Lure.MatchesUA(req.UserAgent()) {
		h.Spoof.ServeHTTP(ctx.ResponseWriter, req)
		return proxy.ErrShortCircuit
	}
	return nil
}

var _ proxy.RequestHandler = (*LureValidator)(nil)
