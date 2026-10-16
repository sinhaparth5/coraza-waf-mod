package proxy

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"

	"palisade/internal/storage"
)

func TestCanonicalRedirect(t *testing.T) {
	apex := &storage.Service{Host: "example.com", HostAliases: []string{"www.example.com"}, CanonicalHost: "example.com"}
	www := &storage.Service{Host: "example.com", HostAliases: []string{"www.example.com"}, CanonicalHost: "www.example.com"}
	cases := []struct {
		name string
		app  *storage.Service
		host string
		url  string
		tls  bool
		xfp  string
		want string
	}{
		{"www to apex keeps path and query", apex, "www.example.com", "/a/b?x=1", true, "", "https://example.com/a/b?x=1"},
		{"already canonical", apex, "example.com", "/", true, "", ""},
		{"canonical, other case", apex, "EXAMPLE.com", "/", true, "", ""},
		{"apex to www", www, "example.com", "/", true, "", "https://www.example.com/"},
		{"keeps port", apex, "www.example.com:8443", "/", true, "", "https://example.com:8443/"},
		{"plain http", apex, "www.example.com", "/", false, "", "http://example.com/"},
		{"tls terminated in front", apex, "www.example.com", "/", false, "https", "https://example.com/"},
		{"no canonical set", &storage.Service{Host: "example.com", HostAliases: []string{"www.example.com"}}, "www.example.com", "/", true, "", ""},
		{"prefix service", &storage.Service{Prefix: "/api", CanonicalHost: "example.com"}, "other.com", "/api", true, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", tc.url, nil)
			r.Host = tc.host
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}
			if tc.xfp != "" {
				r.Header.Set("X-Forwarded-Proto", tc.xfp)
			}
			if got := canonicalRedirect(r, tc.app); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
