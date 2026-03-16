package obfuscator

import (
	"bytes"
	"context"
)

const (
	MarkerStart = "/* __mirage_injected_start__ */"
	MarkerEnd   = "/* __mirage_injected_end__ */"
)

// Pre-allocated byte slices to avoid per-call allocations on the hot path.
var (
	markerStartBytes = []byte(MarkerStart)
	markerEndBytes   = []byte(MarkerEnd)
)

// obfuscateMarkedHTML scans html for injected script blocks delimited by
// MarkerStart and MarkerEnd, calls obfuscate on the content between the
// markers, and returns the modified HTML. All other content is unchanged.
// On obfuscation error for a block, that block is written through as plaintext.
func obfuscateMarkedHTML(ctx context.Context, obfuscate func(context.Context, string) (string, error), html []byte) ([]byte, error) {
	startMarker := markerStartBytes
	endMarker := markerEndBytes

	var out bytes.Buffer
	remaining := html

	for {
		startIdx := bytes.Index(remaining, startMarker)
		if startIdx == -1 {
			out.Write(remaining)
			break
		}
		out.Write(remaining[:startIdx+len(startMarker)])
		remaining = remaining[startIdx+len(startMarker):]

		endIdx := bytes.Index(remaining, endMarker)
		if endIdx == -1 {
			// Malformed: start marker without end marker — write the rest as-is.
			out.Write(remaining)
			break
		}

		scriptContent := remaining[:endIdx]
		remaining = remaining[endIdx:] // starts at MarkerEnd

		obfuscated, err := obfuscate(ctx, string(scriptContent))
		if err != nil {
			// Non-fatal: pass through plaintext and continue.
			out.Write(scriptContent)
		} else {
			out.WriteString(obfuscated)
		}
	}

	return out.Bytes(), nil
}
