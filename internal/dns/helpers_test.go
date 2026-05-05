package dns_test

import (
	"github.com/travisbale/mirage/internal/config"
)

// providerConfig builds a minimal DNSProviderConfig for factory tests.
func providerConfig(provider string) config.DNSProviderConfig {
	return config.DNSProviderConfig{Provider: provider}
}
