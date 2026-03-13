package dns

import (
	"fmt"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/config"
)

// ProviderFactory constructs the concrete provider described by cfg and returns
// it as an aitm.DNSProvider. Calls Ping after construction to fail fast on
// bad credentials or unreachable APIs.
func ProviderFactory(alias string, cfg config.DNSProviderConfig, externalIP string, dnsPort int) (aitm.DNSProvider, error) {
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
			return nil, fmt.Errorf("dns: cloudflare provider %q requires settings.api_token", alias)
		}
		provider, err = NewCloudflareDNSProvider(token)
	case "route53":
		accessKey := cfg.Settings["access_key"]
		secretKey := cfg.Settings["secret_key"]
		if accessKey == "" || secretKey == "" {
			return nil, fmt.Errorf("dns: route53 provider %q requires settings.access_key and settings.secret_key", alias)
		}
		provider, err = NewRoute53DNSProvider(accessKey, secretKey, cfg.Settings["region"])
	case "gandi":
		apiKey := cfg.Settings["api_key"]
		if apiKey == "" {
			return nil, fmt.Errorf("dns: gandi provider %q requires settings.api_key", alias)
		}
		provider, err = NewGandiDNSProvider(apiKey)
	default:
		return nil, fmt.Errorf("dns: unknown provider type %q for %q", cfg.Provider, alias)
	}

	if err != nil {
		return nil, fmt.Errorf("dns: constructing provider %q: %w", alias, err)
	}
	if err := provider.Ping(); err != nil {
		return nil, fmt.Errorf("dns: provider %q ping failed: %w", alias, err)
	}
	return provider, nil
}

// BuildProviders constructs all providers from the config slice and returns
// a map keyed by provider alias. Fails fast if any provider is misconfigured.
func BuildProviders(cfgs []config.DNSProviderConfig, externalIP string, dnsPort int) (map[string]aitm.DNSProvider, error) {
	out := make(map[string]aitm.DNSProvider, len(cfgs))
	for _, cfg := range cfgs {
		provider, err := ProviderFactory(cfg.Alias, cfg, externalIP, dnsPort)
		if err != nil {
			return nil, err
		}
		out[cfg.Alias] = provider
	}
	return out, nil
}
