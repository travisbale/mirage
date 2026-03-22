package dns_test

import (
	"context"
	"strings"
	"testing"

	"github.com/travisbale/mirage/internal/dns"
)

func TestProviderFactory_UnknownType(t *testing.T) {
	_, err := dns.ProviderFactory(context.Background(), providerConfig("unknown"), "1.2.3.4", 53)
	if err == nil {
		t.Error("expected error for unknown provider type")
	}
	if !strings.Contains(err.Error(), "unknown provider type") {
		t.Errorf("error %q does not mention unknown provider type", err.Error())
	}
}
