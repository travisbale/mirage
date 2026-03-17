package request_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
	"github.com/travisbale/mirage/internal/proxy/handlers/request"
)

type stubBotEval struct {
	verdict aitm.BotVerdict
}

func (s *stubBotEval) Evaluate(_ string, _ *aitm.BotTelemetry) aitm.BotVerdict {
	return s.verdict
}

func TestBotGuardCheck_Allow(t *testing.T) {
	spoofer := &stubSpoofer{}
	h := &request.BotGuardCheck{
		Service: &stubBotEval{verdict: aitm.VerdictAllow},
		Spoof:   spoofer,
	}
	ctx := &aitm.ProxyContext{JA4Hash: "t13d1516h2_abc_def"}
	rec := httptest.NewRecorder()
	ctx.ResponseWriter = rec
	req := newReq(http.MethodGet, "https://example.com/", nil)

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spoofer.called {
		t.Error("spoofer should not have been called on allow verdict")
	}
}

func TestBotGuardCheck_Spoof(t *testing.T) {
	spoofer := &stubSpoofer{}
	h := &request.BotGuardCheck{
		Service: &stubBotEval{verdict: aitm.VerdictSpoof},
		Spoof:   spoofer,
	}
	ctx := &aitm.ProxyContext{JA4Hash: "bad-ja4"}
	rec := httptest.NewRecorder()
	ctx.ResponseWriter = rec
	req := newReq(http.MethodGet, "https://example.com/", nil)

	err := h.Handle(ctx, req)
	if !errors.Is(err, proxy.ErrShortCircuit) {
		t.Fatalf("expected ErrShortCircuit, got %v", err)
	}
	if !spoofer.called {
		t.Error("expected spoofer to be called on spoof verdict")
	}
}

func TestBotGuardCheck_Block(t *testing.T) {
	spoofer := &stubSpoofer{}
	h := &request.BotGuardCheck{
		Service: &stubBotEval{verdict: aitm.VerdictBlock},
		Spoof:   spoofer,
	}
	ctx := &aitm.ProxyContext{JA4Hash: "scanner-ja4"}
	rec := httptest.NewRecorder()
	ctx.ResponseWriter = rec
	req := newReq(http.MethodGet, "https://example.com/", nil)

	err := h.Handle(ctx, req)
	if !errors.Is(err, proxy.ErrShortCircuit) {
		t.Fatalf("expected ErrShortCircuit, got %v", err)
	}
	if spoofer.called {
		t.Error("spoofer should NOT be called on block verdict (block = drop)")
	}
}

func TestBotGuardCheck_EmptyJA4_Skips(t *testing.T) {
	h := &request.BotGuardCheck{
		Service: &stubBotEval{verdict: aitm.VerdictSpoof},
		Spoof:   &stubSpoofer{},
	}
	ctx := &aitm.ProxyContext{} // no JA4Hash
	req := newReq(http.MethodGet, "https://example.com/", nil)
	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("expected nil error when JA4 is empty, got %v", err)
	}
}
