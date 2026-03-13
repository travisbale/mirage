package response

import (
	"net/http"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
)

var headersToStrip = []string{
	"Content-Security-Policy",
	"Content-Security-Policy-Report-Only",
	"Strict-Transport-Security",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"X-XSS-Protection",
	"Expect-CT",
	"Cross-Origin-Embedder-Policy",
	"Cross-Origin-Opener-Policy",
	"Cross-Origin-Resource-Policy",
	"Permissions-Policy",
}

// SecurityHeaderStripper removes security headers that would break the AiTM proxy.
type SecurityHeaderStripper struct{}

func (h *SecurityHeaderStripper) Name() string { return "SecurityHeaderStripper" }

func (h *SecurityHeaderStripper) Handle(ctx *aitm.ProxyContext, resp *http.Response) error {
	for _, headerName := range headersToStrip {
		resp.Header.Del(headerName)
	}
	return nil
}

var _ proxy.ResponseHandler = (*SecurityHeaderStripper)(nil)
