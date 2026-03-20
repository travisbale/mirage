package proxy

import (
	_ "embed"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
)

//go:embed spoof_default.html
var spoofDefaultPage []byte

// SpoofProxy renders a legitimate site's content in place of a phishing
// response, making the server appear to host real content.
//
// When no spoof URL is configured, ServeHTTP serves the Apache default page —
// a 200 OK response that makes the server look like an ordinary unconfigured
// web host rather than returning a suspicious empty error response.
type SpoofProxy struct {
	defaultSpoofURL string
	logger          *slog.Logger
	cache           sync.Map // string → *httputil.ReverseProxy
}

func NewSpoofProxy(defaultSpoofURL string, logger *slog.Logger) *SpoofProxy {
	return &SpoofProxy{defaultSpoofURL: defaultSpoofURL, logger: logger}
}

// ServeHTTP spoofs using the default spoof URL, or the Apache default page if none is configured.
func (s *SpoofProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.ServeWithTarget(w, r, "")
}

// ServeWithTarget spoofs using the provided URL, falling back to the default
// spoof URL, and finally to the Apache default page if neither is available.
func (s *SpoofProxy) ServeWithTarget(w http.ResponseWriter, r *http.Request, spoofURL string) {
	if spoofURL == "" {
		spoofURL = s.defaultSpoofURL
	}
	if spoofURL == "" {
		serveDefaultPage(w)
		return
	}

	rp, err := s.reverseProxyFor(spoofURL)
	if err != nil {
		s.logger.Error("invalid spoof URL", "url", spoofURL, "error", err)
		serveDefaultPage(w)
		return
	}

	rp.ServeHTTP(w, r)
}

func serveDefaultPage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(spoofDefaultPage)
}

func (s *SpoofProxy) reverseProxyFor(spoofURL string) (*httputil.ReverseProxy, error) {
	if v, ok := s.cache.Load(spoofURL); ok {
		return v.(*httputil.ReverseProxy), nil
	}

	target, err := url.Parse(spoofURL)
	if err != nil {
		return nil, err
	}

	rp := httputil.NewSingleHostReverseProxy(target)
	rp.ModifyResponse = stripSpoofResponseHeaders
	s.cache.Store(spoofURL, rp)

	return rp, nil
}

func stripSpoofResponseHeaders(resp *http.Response) error {
	for _, name := range headersToStrip {
		resp.Header.Del(name)
	}
	return nil
}
