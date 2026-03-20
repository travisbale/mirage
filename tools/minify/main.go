// minify minifies the injected JavaScript source files using the esbuild Go API.
// Run via: go run ./tools/minify
// Output is written to internal/proxy/dist/
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/evanw/esbuild/pkg/api"
)

func main() {
	// Resolve paths relative to the repository root regardless of where the tool is invoked from.
	_, toolFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(toolFile), "..", "..")
	scriptsDir := filepath.Join(repoRoot, "scripts")
	distDir := filepath.Join(repoRoot, "internal", "proxy", "dist")

	if err := os.MkdirAll(distDir, 0755); err != nil {
		fatalf("creating dist dir: %v", err)
	}

	scripts := []string{"telemetry.js", "redirect.js"}
	for _, name := range scripts {
		src := filepath.Join(scriptsDir, name)
		dst := filepath.Join(distDir, strings.TrimSuffix(name, ".js")+".min.js")
		minify(src, dst)
	}
}

func minify(src, dst string) {
	result := api.Build(api.BuildOptions{
		EntryPoints:       []string{src},
		Bundle:            false,
		MinifyWhitespace:  true,
		MinifyIdentifiers: true,
		MinifySyntax:      true,
		Target:            api.ES2017,
		Write:             false,
	})

	if len(result.Errors) > 0 {
		for _, e := range result.Errors {
			fmt.Fprintf(os.Stderr, "esbuild error: %s\n", e.Text)
		}
		os.Exit(1)
	}

	if len(result.OutputFiles) != 1 {
		fatalf("expected 1 output file, got %d", len(result.OutputFiles))
	}

	if err := os.WriteFile(dst, result.OutputFiles[0].Contents, 0644); err != nil {
		fatalf("writing %s: %v", dst, err)
	}

	fmt.Printf("minified %s → %s (%d bytes)\n", src, dst, len(result.OutputFiles[0].Contents))
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "minify: "+format+"\n", args...)
	os.Exit(1)
}
