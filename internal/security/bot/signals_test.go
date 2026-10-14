package bot

import (
	"net/http/httptest"
	"slices"
	"testing"
)

func TestAnalyze(t *testing.T) {
	browser := map[string]string{"Accept-Language": "en", "Accept": "*/*", "Accept-Encoding": "gzip"}
	tests := []struct {
		name        string
		ua          string
		headers     map[string]string
		wantScore   int
		wantBot     bool
		wantTrusted bool
		wantSignal  string
	}{
		{"trusted crawler", "Mozilla/5.0 (compatible; Googlebot/2.1)", nil, 0, false, true, "trusted_crawler"},
		{"browser", "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0", browser, 0, false, false, ""},
		{"scanner", "sqlmap/1.7", browser, 10, true, false, "scanner_ua"},
		{"http lib", "curl/8.0.1", browser, 3, false, false, "http_lib_ua"},
		{"short ua", "abc", browser, 2, false, false, "short_ua"},
		{"missing everything", "", nil, 9, false, false, "missing_ua"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.Header.Set("User-Agent", tt.ua)
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}
			a := Analyze(r)
			if a.Score != tt.wantScore || a.IsBot != tt.wantBot || a.IsTrustedCrawler != tt.wantTrusted {
				t.Fatalf("got %+v", a)
			}
			if tt.wantSignal != "" && !slices.Contains(a.Signals, tt.wantSignal) {
				t.Fatalf("signals %v missing %q", a.Signals, tt.wantSignal)
			}
		})
	}
}
