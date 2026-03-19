package response

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
)

type bodyObfuscator interface {
	Obfuscate(ctx context.Context, html []byte) ([]byte, error)
}

// JSObfuscator passes HTML bodies through the configured obfuscator to hide
// injected scripts from static analysis. Only blocks marked with the mirage
// injection markers are obfuscated; third-party scripts are untouched.
type JSObfuscator struct {
	Obfuscator bodyObfuscator
	Logger     *slog.Logger
}

func (h *JSObfuscator) Name() string { return "JSObfuscator" }

func (h *JSObfuscator) Handle(ctx *aitm.ProxyContext, resp *http.Response) error {
	if ctx.Session == nil || !isHTMLResponse(resp) {
		return nil
	}
	body, err := readBody(resp)
	if err != nil {
		return err
	}
	obfuscated, err := h.Obfuscator.Obfuscate(resp.Request.Context(), body)
	if err != nil {
		h.Logger.Warn("js obfuscation failed, using plaintext", "error", err)
		replaceBody(resp, body)
		return nil
	}
	replaceBody(resp, obfuscated)
	return nil
}

var _ proxy.ResponseHandler = (*JSObfuscator)(nil)
