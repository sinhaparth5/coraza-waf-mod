package challenge

import (
	"net/http"
	"testing"
)

func TestExempt(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		want   bool
	}{
		// The cases that motivated the exemption (issue #57).
		{"site.webmanifest at root", http.MethodGet, "/site.webmanifest", true},
		{"manifest.json at root", http.MethodGet, "/manifest.json", true},
		{"webmanifest in a subdirectory", http.MethodGet, "/static/app.webmanifest", true},
		{"manifest.json in a subdirectory", http.MethodGet, "/assets/manifest.json", true},
		{"bare .webmanifest", http.MethodGet, "/.webmanifest", true},
		{"uppercase spelling", http.MethodGet, "/MANIFEST.JSON", true},
		{"HEAD probe", http.MethodHead, "/site.webmanifest", true},

		// Ordinary traffic must stay challengeable.
		{"html page", http.MethodGet, "/index.html", false},
		{"root", http.MethodGet, "/", false},
		{"empty path", http.MethodGet, "", false},
		{"admin path", http.MethodGet, "/admin", false},

		// A manifest fetch is never a write; anything else at that path is
		// not the browser's manifest fetch.
		{"POST to manifest path", http.MethodPost, "/manifest.json", false},
		{"DELETE to webmanifest path", http.MethodDelete, "/site.webmanifest", false},

		// Only the whole final segment counts, so neither a suffixed
		// filename nor a manifest-looking directory earns the exemption.
		{"double extension", http.MethodGet, "/manifest.json.php", false},
		{"backup suffix", http.MethodGet, "/app.webmanifest.bak", false},
		{"prefix only", http.MethodGet, "/manifest.jsonx", false},
		{"manifest as a directory", http.MethodGet, "/manifest.json/../admin", false},
		{"substring of a longer name", http.MethodGet, "/notmanifest.json", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Exempt(tt.method, tt.path); got != tt.want {
				t.Errorf("Exempt(%q, %q) = %v, want %v", tt.method, tt.path, got, tt.want)
			}
		})
	}
}
