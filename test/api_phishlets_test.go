package test_test

import (
	"testing"

	"github.com/travisbale/mirage/sdk"
	"github.com/travisbale/mirage/test"
)

// TestAPI_PhishletEnableDisable verifies that disabling and re-enabling a
// phishlet via the API is reflected in ListPhishlets.
func TestAPI_PhishletEnableDisable(t *testing.T) {
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

// TestAPI_PhishletHideUnhide verifies that hiding and unhiding a phishlet is
// reflected in its config. Hiding does not affect routing.
func TestAPI_PhishletHideUnhide(t *testing.T) {
	harness := test.NewHarness(t)

	if _, err := harness.API.HidePhishlet("testsite"); err != nil {
		t.Fatalf("HidePhishlet: %v", err)
	}

	phishlets, err := harness.API.ListPhishlets()
	if err != nil {
		t.Fatalf("ListPhishlets: %v", err)
	}
	for _, p := range phishlets.Items {
		if p.Name == "testsite" && !p.Hidden {
			t.Error("expected testsite to be hidden")
		}
	}

	if _, err := harness.API.UnhidePhishlet("testsite"); err != nil {
		t.Fatalf("UnhidePhishlet: %v", err)
	}

	phishlets, err = harness.API.ListPhishlets()
	if err != nil {
		t.Fatalf("ListPhishlets after unhide: %v", err)
	}
	for _, p := range phishlets.Items {
		if p.Name == "testsite" && p.Hidden {
			t.Error("expected testsite to be unhidden after unhide")
		}
	}
}
