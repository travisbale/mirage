package request_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
	"github.com/travisbale/mirage/internal/proxy/handlers/request"
)

type stubIPBlocker struct{ block bool }

func (s *stubIPBlocker) IsBlocked(_ string) bool { return s.block }

func TestBlacklistChecker_NotBlocked(t *testing.T) {
	spoofer := &stubSpoofer{}
	h := &request.BlacklistChecker{
		Service: &stubIPBlocker{block: false},
		Spoof:   spoofer,
	}
	ctx := &aitm.ProxyContext{ClientIP: "1.2.3.4"}
	rec := httptest.NewRecorder()
	ctx.ResponseWriter = rec
	req := newReq(http.MethodGet, "https://example.com/", nil)

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spoofer.called {
		t.Error("spoofer should not be called when IP is not blocked")
	}
}

func TestBlacklistChecker_Blocked(t *testing.T) {
	spoofer := &stubSpoofer{}
	h := &request.BlacklistChecker{
		Service: &stubIPBlocker{block: true},
		Spoof:   spoofer,
	}
	ctx := &aitm.ProxyContext{ClientIP: "1.2.3.4"}
	rec := httptest.NewRecorder()
	ctx.ResponseWriter = rec
	req := newReq(http.MethodGet, "https://example.com/", nil)

	err := h.Handle(ctx, req)
	if err != proxy.ErrShortCircuit {
		t.Fatalf("expected ErrShortCircuit, got %v", err)
	}
	if !spoofer.called {
		t.Error("expected spoofer to be called on blocked IP")
	}
}
