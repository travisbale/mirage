package test_test

import (
	"testing"

	"github.com/travisbale/mirage/sdk"
	"github.com/travisbale/mirage/test"
)

// TestAPI_PhishletEnableDisable verifies that disabling and re-enabling a
// phishlet via the API is reflected in ListPhishlets.
func TestAPI_PhishletEnableDisable(t *testing.T) {
	t.Parallel()
	harness := test.NewHarness(t)

	// Disable the already-enabled phishlet.
	if _, err := harness.API.DisablePhishlet("testsite"); err != nil {
		t.Fatalf("DisablePhishlet: %v", err)
	}

	phishlets, err := harness.API.ListPhishlets()
	if err != nil {
		t.Fatalf("ListPhishlets: %v", err)
	}
	for _, p := range phishlets.Items {
		if p.Name == "testsite" && p.Enabled {
			t.Error("expected testsite to be disabled")
		}
	}

	// Re-enable it.
	if _, err := harness.API.EnablePhishlet("testsite", sdk.EnablePhishletRequest{
		Hostname: "login.phish.test",
	}); err != nil {
		t.Fatalf("EnablePhishlet: %v", err)
	}

	phishlets, err = harness.API.ListPhishlets()
	if err != nil {
		t.Fatalf("ListPhishlets after enable: %v", err)
	}
	for _, p := range phishlets.Items {
		if p.Name == "testsite" && !p.Enabled {
			t.Error("expected testsite to be enabled after re-enable")
		}
	}
}
