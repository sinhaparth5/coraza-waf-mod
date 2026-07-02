package ui

import (
	"testing"

	"coraza-waf-mod/storage"
)

func TestUniqueCertName(t *testing.T) {
	existing := []storage.CertRecord{{Name: "cert"}, {Name: "example.com"}}

	cases := []struct {
		name      string
		requested string
		domains   []string
		want      string
	}{
		{"free name kept", "my-cert", nil, "my-cert"},
		{"collision falls back to domain", "cert", []string{"*.example2.com", "example2.com"}, "example2.com"},
		{"collision with taken domain gets suffix", "cert", []string{"example.com"}, "cert-2"},
		{"collision with no domains gets suffix", "cert", nil, "cert-2"},
		{"case-insensitive collision", "CERT", []string{"example2.com"}, "example2.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := uniqueCertName(tc.requested, tc.domains, existing); got != tc.want {
				t.Errorf("uniqueCertName(%q, %v) = %q, want %q", tc.requested, tc.domains, got, tc.want)
			}
		})
	}

	// Suffix search must skip already-taken numbered names.
	got := uniqueCertName("cert", nil, []storage.CertRecord{{Name: "cert"}, {Name: "cert-2"}})
	if got != "cert-3" {
		t.Errorf("expected cert-3, got %q", got)
	}
}
