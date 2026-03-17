package request_test

import (
	"net/http"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy/handlers/request"
)

func TestJA4Extractor_NilHello_NoError(t *testing.T) {
	h := &request.JA4Extractor{}
	ctx := &aitm.ProxyContext{}
	req := newReq(http.MethodGet, "https://example.com/", nil)
	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.JA4Hash != "" {
		t.Errorf("expected empty JA4Hash, got %q", ctx.JA4Hash)
	}
}
