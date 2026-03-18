package request

import (
	"net/http"
	"strings"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
)

// APIRouter hands off to the REST API handler when the request Host matches
// the configured secret operator hostname.
type APIRouter struct {
	SecretHostname string
	Handler        http.Handler
}

func (h *APIRouter) Name() string { return "APIRouter" }

func (h *APIRouter) Handle(ctx *aitm.ProxyContext, req *http.Request) error {
	if strings.EqualFold(hostWithoutPort(req.Host), h.SecretHostname) {
		h.Handler.ServeHTTP(ctx.ResponseWriter, req)
		return proxy.ErrShortCircuit
	}

	return nil
}

var _ proxy.RequestHandler = (*APIRouter)(nil)
