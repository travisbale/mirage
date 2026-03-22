package dns

import (
	"context"
	"fmt"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/config"
)

// ProviderFactory constructs the concrete provider described by cfg and returns
// it as an aitm.DNSProvider. Calls Ping after construction to fail fast on
// bad credentials or unreachable APIs.
func ProviderFactory(ctx context.Context, cfg config.DNSProviderConfig, externalIP string, dnsPort int) (aitm.DNSProvider, error) {
	var (
		provider aitm.DNSProvider
		err      error
	)

	switch cfg.Provider {
	case "builtin", "":
		provider, err = NewBuiltInDNSProvider(externalIP, dnsPort)
	case "cloudflare":
		token := cfg.Settings["api_token"]
		if token == "" {
			return nil, fmt.Errorf("dns: cloudflare provider %q requires settings.api_token", cfg.Alias)
		}
		provider, err = NewCloudflareDNSProvider(token)
	case "route53":
		accessKey := cfg.Settings["access_key"]
		secretKey := cfg.Settings["secret_key"]
		if accessKey == "" || secretKey == "" {
			return nil, fmt.Errorf("dns: route53 provider %q requires settings.access_key and settings.secret_key", cfg.Alias)
		}
		provider, err = NewRoute53DNSProvider(ctx, accessKey, secretKey, cfg.Settings["region"])
	case "gandi":
		apiKey := cfg.Settings["api_key"]
		if apiKey == "" {
			return nil, fmt.Errorf("dns: gandi provider %q requires settings.api_key", cfg.Alias)
		}
		provider, err = NewGandiDNSProvider(apiKey)
	default:
		return nil, fmt.Errorf("dns: unknown provider type %q for %q", cfg.Provider, cfg.Alias)
	}

	if err != nil {
		return nil, fmt.Errorf("dns: constructing provider %q: %w", cfg.Alias, err)
	}
	if err := provider.Ping(ctx); err != nil {
		return nil, fmt.Errorf("dns: provider %q ping failed: %w", cfg.Alias, err)
	}
	return provider, nil
}

// BuildProviders constructs all providers from the config slice and returns
// a map keyed by provider alias. Fails fast if any provider is misconfigured.
func BuildProviders(ctx context.Context, cfgs []config.DNSProviderConfig, externalIP string, dnsPort int) (map[string]aitm.DNSProvider, error) {
	out := make(map[string]aitm.DNSProvider, len(cfgs))
	for _, cfg := range cfgs {
		provider, err := ProviderFactory(ctx, cfg, externalIP, dnsPort)
		if err != nil {
			return nil, err
		}
		out[cfg.Alias] = provider
	}
	return out, nil
}
