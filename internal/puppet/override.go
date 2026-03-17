package puppet

import (
	"encoding/json"
	"fmt"
	"strings"
)

// OverrideBuilder converts raw telemetry into a JS IIFE that overrides
// browser properties to match a real Chromium visit.
type OverrideBuilder struct{}

type overrideSpec struct {
	telemetryKey string
	jsObject     string // "navigator" or "screen"
	jsProperty   string
}

var overrideSpecs = []overrideSpec{
	{"userAgent", "navigator", "userAgent"},
	{"platform", "navigator", "platform"},
	{"language", "navigator", "language"},
	{"hardwareConcurrency", "navigator", "hardwareConcurrency"},
	{"deviceMemory", "navigator", "deviceMemory"},
	{"screenWidth", "screen", "width"},
	{"screenHeight", "screen", "height"},
	{"colorDepth", "screen", "colorDepth"},
}

// BuildOverride generates a self-executing JS snippet that overrides
// navigator and screen properties with the values collected from the
// real target site.
func (b *OverrideBuilder) BuildOverride(telemetry map[string]any) string {
	if len(telemetry) == 0 {
		return ""
	}

	var lines []string
	for _, spec := range overrideSpecs {
		val, ok := telemetry[spec.telemetryKey]
		if !ok || val == nil {
			continue
		}
		encoded, err := json.Marshal(val)
		if err != nil {
			continue
		}
		lines = append(lines, fmt.Sprintf(
			"Object.defineProperty(%s,%q,{get:function(){return %s}})",
			spec.jsObject, spec.jsProperty, encoded))
	}

	if len(lines) == 0 {
		return ""
	}

	return "(function(){" + strings.Join(lines, ";") + "})();"
}
