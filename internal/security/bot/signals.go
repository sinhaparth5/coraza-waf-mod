package bot

import (
	"net/http"
	"strings"
)

// trustedCrawlers are legitimate bots from search engines, social platforms,
// and analytics tools that should never be challenged. Matched case-insensitively
// against the User-Agent substring.
//
// NOTE: UA strings are trivially spoofable. The JS challenge is a thin
// pre-filter; the Coraza WAF inspects every request regardless and will catch
// actual attack payloads even from clients impersonating Googlebot.
var trustedCrawlers = []string{
	// Google
	"googlebot", "google-inspectiontool", "googleother",
	"adsbot-google", "google-read-aloud", "mediapartners-google",
	// Bing / Microsoft
	"bingbot", "bingpreview", "msnbot", "adidxbot",
	// Apple
	"applebot",
	// DuckDuckGo
	"duckduckbot", "duckduckgo-favicons-bot",
	// Yahoo
	"slurp",
	// Yandex
	"yandexbot", "yandexmobilebot",
	// Baidu
	"baiduspider",
	// Facebook / Meta (link preview)
	"facebookexternalhit", "facebot",
	// Twitter / X (link preview)
	"twitterbot",
	// LinkedIn (link preview)
	"linkedinbot",
	// Pinterest
	"pinterest/",
	// Telegram (link preview)
	"telegrambot",
	// Slack (link preview)
	"slackbot",
	// Discord (link preview)
	"discordbot",
	// WhatsApp (link preview)
	"whatsapp/",
	// Archive.org
	"ia_archiver", "archive.org_bot",
}

// knownScanners are attack/audit tools that always get a high score.
var knownScanners = []string{
	"nikto", "nuclei", "sqlmap", "nmap/", "masscan", "zgrab",
	"dirbuster", "gobuster", "wfuzz", "ffuf", "hydra", "burpsuite",
	"zap/", "nessus", "openvas",
}

// httpLibFragments are generic HTTP client libraries — suspicious but not
// necessarily malicious; scored lower so they can't cross the threshold alone.
var httpLibFragments = []string{
	"curl/", "python-requests/", "python-urllib", "python/",
	"go-http-client/", "wget/", "libwww-perl/", "scrapy/",
	"okhttp/", "restsharp", "apache-httpclient", "java/",
	"axios/", "node-fetch", "node.js", "phpunit",
}

// Analysis is the result of inspecting one HTTP request for bot-like signals.
type Analysis struct {
	Score            int
	Signals          []string
	IsBot            bool // true if a confirmed attack/scanner tool was detected
	IsTrustedCrawler bool // true if UA matches a known-good SEO/social crawler
}

// Analyze scores r for bot-like characteristics. It is designed to be fast
// (only reads headers already parsed by net/http) and called on every request.
func Analyze(r *http.Request) Analysis {
	var a Analysis
	ua := r.Header.Get("User-Agent")
	uaLow := strings.ToLower(ua)

	// Trusted crawlers bypass all scoring and are never challenged.
	// They still pass through the Coraza WAF for payload inspection.
	for _, s := range trustedCrawlers {
		if strings.Contains(uaLow, s) {
			a.IsTrustedCrawler = true
			a.Signals = append(a.Signals, "trusted_crawler")
			return a
		}
	}

	switch ua {
	case "":
		a.add(5, "missing_ua")
	default:
		for _, s := range knownScanners {
			if strings.Contains(uaLow, s) {
				a.add(10, "scanner_ua")
				a.IsBot = true
				break
			}
		}
		if !a.IsBot {
			for _, s := range httpLibFragments {
				if strings.Contains(uaLow, s) {
					a.add(3, "http_lib_ua")
					break
				}
			}
		}
		if !a.IsBot && len(ua) < 10 {
			a.add(2, "short_ua")
		}
	}

	if r.Header.Get("Accept-Language") == "" {
		a.add(2, "no_accept_language")
	}
	if r.Header.Get("Accept") == "" {
		a.add(1, "no_accept")
	}
	if r.Header.Get("Accept-Encoding") == "" {
		a.add(1, "no_accept_encoding")
	}

	return a
}

func (a *Analysis) add(n int, signal string) {
	a.Score += n
	a.Signals = append(a.Signals, signal)
}
