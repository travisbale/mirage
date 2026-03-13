package request

import (
	"net"
	"net/http"
	"strings"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
)

// IPExtractor resolves the true client IP, honouring trusted CDN proxy headers.
type IPExtractor struct {
	TrustedCIDRs []*net.IPNet
}

func (h *IPExtractor) Name() string { return "IPExtractor" }

func (h *IPExtractor) Handle(ctx *aitm.ProxyContext, req *http.Request) error {
	socketIP := extractSocketIP(req.RemoteAddr)
	if h.isTrustedProxy(socketIP) {
		if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
			ctx.ClientIP = firstIP(xff)
			return nil
		}
		if tci := req.Header.Get("True-Client-IP"); tci != "" {
			ctx.ClientIP = tci
			return nil
		}
	}
	ctx.ClientIP = socketIP
	return nil
}

func (h *IPExtractor) isTrustedProxy(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range h.TrustedCIDRs {
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

func extractSocketIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func firstIP(xff string) string {
	parts := strings.SplitN(xff, ",", 2)
	return strings.TrimSpace(parts[0])
}

var _ proxy.RequestHandler = (*IPExtractor)(nil)
