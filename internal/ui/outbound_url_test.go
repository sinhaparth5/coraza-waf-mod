package ui

import "testing"

// TestValidateOutboundURL pins the rule for URLs the server itself fetches:
// absolute http/https only; anything that could reach non-HTTP surfaces
// (file:, gopher:, scheme-relative, bare hosts) is rejected at save time.
func TestValidateOutboundURL(t *testing.T) {
	valid := []string{
		"http://example.com/list.txt",
		"https://feeds.example.com:8443/ips",
		"http://10.0.0.5:8088/services/collector", // LAN SIEM endpoints are legitimate
		"http://localhost:3100/loki/api/v1/push",
	}
	for _, u := range valid {
		if err := validateOutboundURL(u); err != nil {
			t.Errorf("validateOutboundURL(%q) = %v, want nil", u, err)
		}
	}

	invalid := []string{
		"",
		"example.com/list.txt", // no scheme
		"//example.com/list",   // scheme-relative
		"file:///etc/passwd",
		"gopher://example.com/",
		"ftp://example.com/list.txt",
		"http://",
		"ht tp://example.com",
	}
	for _, u := range invalid {
		if err := validateOutboundURL(u); err == nil {
			t.Errorf("validateOutboundURL(%q) = nil, want error", u)
		}
	}
}
