package request_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
	"github.com/travisbale/mirage/internal/proxy/handlers/request"
)

func compiledLure(uaFilter string) *aitm.Lure {
	l := &aitm.Lure{UAFilter: uaFilter}
	if err := l.CompileUA(); err != nil {
		panic(err)
	}
	return l
}

func TestLureValidator_NoLure_Skips(t *testing.T) {
	h := &request.LureValidator{Spoof: &stubSpoofer{}}
	ctx := &aitm.ProxyContext{} // Lure is nil
	req := newReq(http.MethodGet, "https://example.com/", nil)
	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLureValidator_PausedLure_Spoofs(t *testing.T) {
	spoofer := &stubSpoofer{}
	h := &request.LureValidator{Spoof: spoofer}
	pausedUntil := time.Now().Add(time.Hour)
	ctx := &aitm.ProxyContext{
		Lure:           &aitm.Lure{PausedUntil: pausedUntil},
		ResponseWriter: httptest.NewRecorder(),
	}
	req := newReq(http.MethodGet, "https://example.com/", nil)
	if err := h.Handle(ctx, req); !errors.Is(err, proxy.ErrShortCircuit) {
		t.Fatalf("expected ErrShortCircuit, got %v", err)
	}
	if !spoofer.called {
		t.Error("expected spoofer to be called for paused lure")
	}
}

func TestLureValidator_UAFilterMatch_Passes(t *testing.T) {
	h := &request.LureValidator{Spoof: &stubSpoofer{}}
	ctx := &aitm.ProxyContext{Lure: compiledLure("Mozilla")}
	req := newReq(http.MethodGet, "https://example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0)")
	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLureValidator_UAFilterNoMatch_Spoofs(t *testing.T) {
	spoofer := &stubSpoofer{}
	h := &request.LureValidator{Spoof: spoofer}
	ctx := &aitm.ProxyContext{
		Lure:           compiledLure("Mozilla"),
		ResponseWriter: httptest.NewRecorder(),
	}
	req := newReq(http.MethodGet, "https://example.com/", nil)
	req.Header.Set("User-Agent", "Googlebot/2.1")
	if err := h.Handle(ctx, req); !errors.Is(err, proxy.ErrShortCircuit) {
		t.Fatalf("expected ErrShortCircuit, got %v", err)
	}
	if !spoofer.called {
		t.Error("expected spoofer for UA filter mismatch")
	}
}
