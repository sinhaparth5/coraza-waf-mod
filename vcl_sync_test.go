package main

import (
	"os"
	"strings"
	"testing"
)

// TestInstallVCLMatchesDefault guards against the installer's embedded VCL
// drifting from deploy/varnish/default.vcl. install.sh runs via curl|bash with
// no repo checkout, so it carries its own heredoc copy — and that copy once
// silently lacked PURGE, service tagging, session partitioning and TTL tuning
// (#85), breaking all of them on every scripted install.
func TestInstallVCLMatchesDefault(t *testing.T) {
	want, err := os.ReadFile("deploy/varnish/default.vcl")
	if err != nil {
		t.Fatal(err)
	}
	sh, err := os.ReadFile("deploy/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	const open = "write_file \"$VARNISH_VCL_PATH\" <<'VCL'\n"
	_, body, ok := strings.Cut(string(sh), open)
	if !ok {
		t.Fatal("install.sh: VCL heredoc not found")
	}
	body, _, ok = strings.Cut(body, "\nVCL\n")
	if !ok {
		t.Fatal("install.sh: VCL heredoc terminator not found")
	}
	if body+"\n" != string(want) {
		t.Error("install.sh's VCL heredoc differs from deploy/varnish/default.vcl — copy the file into the heredoc verbatim")
	}
}
