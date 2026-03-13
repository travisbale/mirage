package response

import (
	"log/slog"
	"net/http"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
)

// ScriptObfuscator obfuscates marked script blocks in HTML responses.
type ScriptObfuscator interface {
	ObfuscateMarked(body []byte) ([]byte, error)
}

// NoOpObfuscator is a pass-through used when obfuscation is disabled.
type NoOpObfuscator struct{}

func (n *NoOpObfuscator) ObfuscateMarked(body []byte) ([]byte, error) { return body, nil }

// JSObfuscator passes HTML bodies through the configured obfuscator to hide
// injected scripts from analysis.
type JSObfuscator struct {
	Obfuscator ScriptObfuscator
	Logger     *slog.Logger
}

func (h *JSObfuscator) Name() string { return "JSObfuscator" }

func (h *JSObfuscator) Handle(ctx *aitm.ProxyContext, resp *http.Response) error {
	if !isHTMLResponse(resp) {
		return nil
	}
	bodyBytes, err := readBody(resp)
	if err != nil {
		return err
	}
	obfuscated, err := h.Obfuscator.ObfuscateMarked(bodyBytes)
	if err != nil {
		h.Logger.Warn("js obfuscation failed, using plaintext", "error", err)
		replaceBody(resp, bodyBytes)
		return nil
	}
	replaceBody(resp, obfuscated)
	return nil
}

var _ proxy.ResponseHandler = (*JSObfuscator)(nil)
