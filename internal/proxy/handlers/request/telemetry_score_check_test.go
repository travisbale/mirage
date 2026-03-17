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

type stubTelemetryScorer struct{ score float64 }

func (s *stubTelemetryScorer) ScoreSession(_ string) float64 { return s.score }

func TestTelemetryScoreCheck_BelowThreshold_Passes(t *testing.T) {
	h := &request.TelemetryScoreCheck{
		Scorer:    &stubTelemetryScorer{score: 0.3},
		Spoof:     &stubSpoofer{},
		Threshold: 0.8,
	}
	ctx := &aitm.ProxyContext{
		Session:    &aitm.Session{ID: "sess-1"},
		BotVerdict: aitm.VerdictAllow,
	}
	req := newReq(http.MethodGet, "https://example.com/", nil)

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.Session.BotScore != 0.3 {
		t.Errorf("expected BotScore=0.3, got %f", ctx.Session.BotScore)
	}
}

func TestTelemetryScoreCheck_AboveThreshold_Spoofs(t *testing.T) {
	spoofer := &stubSpoofer{}
	h := &request.TelemetryScoreCheck{
		Scorer:    &stubTelemetryScorer{score: 0.95},
		Spoof:     spoofer,
		Threshold: 0.8,
	}
	ctx := &aitm.ProxyContext{
		Session:        &aitm.Session{ID: "sess-1"},
		BotVerdict:     aitm.VerdictAllow,
		ResponseWriter: httptest.NewRecorder(),
	}
	req := newReq(http.MethodGet, "https://example.com/", nil)

	err := h.Handle(ctx, req)
	if !errors.Is(err, proxy.ErrShortCircuit) {
		t.Fatalf("expected ErrShortCircuit, got %v", err)
	}
	if !spoofer.called {
		t.Error("expected spoofer for high bot score")
	}
	if ctx.BotVerdict != aitm.VerdictSpoof {
		t.Errorf("expected VerdictSpoof, got %v", ctx.BotVerdict)
	}
}

func TestTelemetryScoreCheck_NilSession_Skips(t *testing.T) {
	h := &request.TelemetryScoreCheck{
		Scorer:    &stubTelemetryScorer{score: 0.99},
		Spoof:     &stubSpoofer{},
		Threshold: 0.5,
	}
	ctx := &aitm.ProxyContext{BotVerdict: aitm.VerdictAllow}
	req := newReq(http.MethodGet, "https://example.com/", nil)

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTelemetryScoreCheck_NonAllowVerdict_Skips(t *testing.T) {
	h := &request.TelemetryScoreCheck{
		Scorer:    &stubTelemetryScorer{score: 0.99},
		Spoof:     &stubSpoofer{},
		Threshold: 0.5,
	}
	ctx := &aitm.ProxyContext{
		Session:    &aitm.Session{ID: "sess-1"},
		BotVerdict: aitm.VerdictSpoof, // already spoofed
	}
	req := newReq(http.MethodGet, "https://example.com/", nil)

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
