package puppet

import (
	"strings"
	"testing"
)

func TestBuildOverride_EmptyTelemetry(t *testing.T) {
	builder := &OverrideBuilder{}

	if got := builder.BuildOverride(nil); got != "" {
		t.Errorf("nil telemetry: got %q, want empty", got)
	}
	if got := builder.BuildOverride(map[string]any{}); got != "" {
		t.Errorf("empty telemetry: got %q, want empty", got)
	}
}

func TestBuildOverride_UnknownKeysIgnored(t *testing.T) {
	builder := &OverrideBuilder{}
	got := builder.BuildOverride(map[string]any{"bogusKey": "value"})
	if got != "" {
		t.Errorf("unknown key: got %q, want empty", got)
	}
}

func TestBuildOverride_StringProperty(t *testing.T) {
	builder := &OverrideBuilder{}
	got := builder.BuildOverride(map[string]any{
		"userAgent": "Mozilla/5.0 TestAgent",
	})

	if !strings.HasPrefix(got, "(function(){") || !strings.HasSuffix(got, "})();") {
		t.Fatalf("not wrapped in IIFE: %q", got)
	}
	if !strings.Contains(got, `Object.defineProperty(navigator,"userAgent"`) {
		t.Errorf("missing navigator.userAgent override: %q", got)
	}
	if !strings.Contains(got, `"Mozilla/5.0 TestAgent"`) {
		t.Errorf("missing UA value: %q", got)
	}
}

func TestBuildOverride_NumericProperty(t *testing.T) {
	builder := &OverrideBuilder{}
	got := builder.BuildOverride(map[string]any{
		"screenWidth": float64(1920),
	})

	if !strings.Contains(got, `Object.defineProperty(screen,"width"`) {
		t.Errorf("missing screen.width override: %q", got)
	}
	if !strings.Contains(got, "1920") {
		t.Errorf("missing width value: %q", got)
	}
}

func TestBuildOverride_NilValueSkipped(t *testing.T) {
	builder := &OverrideBuilder{}
	got := builder.BuildOverride(map[string]any{
		"deviceMemory": nil,
		"userAgent":    "TestAgent",
	})

	if strings.Contains(got, "deviceMemory") {
		t.Errorf("nil value should be skipped: %q", got)
	}
	if !strings.Contains(got, "userAgent") {
		t.Errorf("non-nil value should be present: %q", got)
	}
}

func TestBuildOverride_MultipleProperties(t *testing.T) {
	builder := &OverrideBuilder{}
	got := builder.BuildOverride(map[string]any{
		"userAgent":   "TestAgent",
		"platform":    "Linux x86_64",
		"screenWidth": float64(1920),
		"colorDepth":  float64(24),
	})

	expected := []string{
		`Object.defineProperty(navigator,"userAgent"`,
		`Object.defineProperty(navigator,"platform"`,
		`Object.defineProperty(screen,"width"`,
		`Object.defineProperty(screen,"colorDepth"`,
	}
	for _, want := range expected {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in output: %q", want, got)
		}
	}

	// Verify properties are semicolon-separated inside the IIFE.
	inner := got[len("(function(){") : len(got)-len("})();")]
	parts := strings.Split(inner, ";")
	if len(parts) != 4 {
		t.Errorf("expected 4 property overrides, got %d", len(parts))
	}
}

func TestBuildOverride_AllKnownKeys(t *testing.T) {
	builder := &OverrideBuilder{}
	telemetry := map[string]any{
		"userAgent":           "TestAgent",
		"platform":            "Linux",
		"language":            "en-US",
		"hardwareConcurrency": float64(8),
		"deviceMemory":        float64(16),
		"screenWidth":         float64(1920),
		"screenHeight":        float64(1080),
		"colorDepth":          float64(24),
	}
	got := builder.BuildOverride(telemetry)

	inner := got[len("(function(){") : len(got)-len("})();")]
	parts := strings.Split(inner, ";")
	if len(parts) != len(overrideSpecs) {
		t.Errorf("expected %d overrides, got %d", len(overrideSpecs), len(parts))
	}
}
