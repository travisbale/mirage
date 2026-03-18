package request

import (
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
)

func TestContextSpoofURL_NeitherConfigured_ReturnsEmpty(t *testing.T) {
	ctx := &aitm.ProxyContext{}
	if got := contextSpoofURL(ctx); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestContextSpoofURL_PhishletOnly_ReturnsPhishletURL(t *testing.T) {
	ctx := &aitm.ProxyContext{
		Phishlet: &aitm.Phishlet{SpoofURL: "https://microsoft.com"},
	}
	if got := contextSpoofURL(ctx); got != "https://microsoft.com" {
		t.Errorf("expected phishlet spoof URL, got %q", got)
	}
}

func TestContextSpoofURL_LureOnly_ReturnsLureURL(t *testing.T) {
	ctx := &aitm.ProxyContext{
		Lure: &aitm.Lure{SpoofURL: "https://lure.example.com"},
	}
	if got := contextSpoofURL(ctx); got != "https://lure.example.com" {
		t.Errorf("expected lure spoof URL, got %q", got)
	}
}

func TestContextSpoofURL_BothConfigured_LureTakesPrecedence(t *testing.T) {
	ctx := &aitm.ProxyContext{
		Phishlet: &aitm.Phishlet{SpoofURL: "https://microsoft.com"},
		Lure:     &aitm.Lure{SpoofURL: "https://lure.example.com"},
	}
	if got := contextSpoofURL(ctx); got != "https://lure.example.com" {
		t.Errorf("expected lure URL to take precedence, got %q", got)
	}
}

func TestContextSpoofURL_LureWithNoURL_FallsBackToPhishlet(t *testing.T) {
	ctx := &aitm.ProxyContext{
		Phishlet: &aitm.Phishlet{SpoofURL: "https://microsoft.com"},
		Lure:     &aitm.Lure{},
	}
	if got := contextSpoofURL(ctx); got != "https://microsoft.com" {
		t.Errorf("expected phishlet spoof URL as fallback, got %q", got)
	}
}
