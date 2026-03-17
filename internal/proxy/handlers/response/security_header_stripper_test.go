package response_test

import (
	"net/http"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy/handlers/response"
)

func TestSecurityHeaderStripper_RemovesAllHeaders(t *testing.T) {
	h := &response.SecurityHeaderStripper{}
	resp := newResp(http.StatusOK, "text/html", "")
	headersToCheck := []string{
		"Content-Security-Policy",
		"Strict-Transport-Security",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"X-XSS-Protection",
	}
	for _, header := range headersToCheck {
		resp.Header.Set(header, "some-value")
	}

	if err := h.Handle(&aitm.ProxyContext{}, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, header := range headersToCheck {
		if resp.Header.Get(header) != "" {
			t.Errorf("expected %s to be stripped, still present", header)
		}
	}
}
