package request

import (
	"net/http"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/botguard"
	"github.com/travisbale/mirage/internal/proxy"
)

// JA4Extractor computes the JA4 fingerprint from the captured ClientHello bytes
// and stores it on the ProxyContext for downstream handlers.
type JA4Extractor struct{}

func (h *JA4Extractor) Name() string { return "JA4Extractor" }

func (h *JA4Extractor) Handle(ctx *aitm.ProxyContext, req *http.Request) error {
	if len(ctx.ClientHelloBytes) == 0 {
		return nil
	}
	hash, err := botguard.ComputeJA4(ctx.ClientHelloBytes)
	if err != nil {
		return nil
	}
	ctx.JA4Hash = hash
	return nil
}

var _ proxy.RequestHandler = (*JA4Extractor)(nil)
