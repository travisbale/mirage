package request

import (
	"net/http"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
)

// IPBlocker checks whether an IP is on the blocklist.
type IPBlocker interface {
	IsBlocked(ip string) bool
}

// BlacklistChecker drops or spoofs connections from blocked IPs.
type BlacklistChecker struct {
	Service IPBlocker
	Spoof   spoofer
}

func (h *BlacklistChecker) Name() string { return "BlacklistChecker" }

func (h *BlacklistChecker) Handle(ctx *aitm.ProxyContext, req *http.Request) error {
	if h.Service.IsBlocked(ctx.ClientIP) {
		h.Spoof.ServeHTTP(ctx.ResponseWriter, req)
		return proxy.ErrShortCircuit
	}
	return nil
}

var _ proxy.RequestHandler = (*BlacklistChecker)(nil)
