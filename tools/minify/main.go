// Command minify reads every .js file in static/js/src and writes a
// minified .min.js counterpart into static/js/dist, which the ui package
// embeds and serves. Run via `go generate` (see main.go) or `make build`.
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/tdewolff/minify/v2"
	"github.com/tdewolff/minify/v2/js"
)

const (
	srcDir = "static/js/src"
	dstDir = "static/js/dist"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return fmt.Errorf("read %s: %w", srcDir, err)
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dstDir, err)
	}

	m := minify.New()
	m.AddFunc("text/javascript", js.Minify)

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".js") {
			continue
		}
		srcPath := filepath.Join(srcDir, e.Name())
		dstName := strings.TrimSuffix(e.Name(), ".js") + ".min.js"
		dstPath := filepath.Join(dstDir, dstName)

		src, err := os.ReadFile(srcPath)
		if err != nil {
			return fmt.Errorf("read %s: %w", srcPath, err)
		}

		out, err := m.String("text/javascript", string(src))
		if err != nil {
			return fmt.Errorf("minify %s: %w", srcPath, err)
		}

		if err := os.WriteFile(dstPath, []byte(out), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", dstPath, err)
		}
		fmt.Printf("minified %s -> %s (%d -> %d bytes)\n", srcPath, dstPath, len(src), len(out))
	}
	return nil
}
