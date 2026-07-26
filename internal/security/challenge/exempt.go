package challenge

import (
	"net/http"
	"strings"
)

// Exempt reports whether a request is structurally incapable of passing the
// challenge gate and must therefore skip it.
//
// Today that is exactly one case: the web app manifest. Per the Web App
// Manifest spec the browser fetches it with credentials omitted unless the
// <link rel="manifest"> carries crossorigin="use-credentials", so the
// cz_bot_ok bypass cookie is never sent — not even from a tab that solved the
// PoW seconds earlier. Challenging it is doubly wrong: the 307 hands the
// browser HTML where it expected application/manifest+json (so the manifest
// silently fails to apply — no Android install prompt, no theme color), and
// every page load leaves an unsolved bot_challenge row behind. Autoban scores
// those at 1 point each, so an ordinary Android visitor reliably accumulates
// its way to a permanent IP ban just by reloading the site.
//
// The exemption keys off the request *path*, deliberately not off the
// Sec-Fetch-Dest: manifest or Accept: application/manifest+json headers the
// same fetch carries. Those headers are trivially settable by any client, so
// trusting them would let an attacker skip the challenge on *any* path with
// one header; keying off the path means the most a spoofer gains is
// unchallenged access to a static, public JSON file. This skips the challenge
// gate only — IP blocklist, geo blocking, rate limiting and the WAF all still
// run on these requests.
func Exempt(method, path string) bool {
	// A manifest is fetched with GET (HEAD allowed for probes/cache
	// revalidation). Anything else at the same path is not a manifest fetch.
	if method != http.MethodGet && method != http.MethodHead {
		return false
	}

	// Match the last path segment only, so "/x/manifest.json/../admin" (whose
	// final segment is "admin") is not exempted.
	name := path
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	name = strings.ToLower(name)

	// ".webmanifest" is the registered extension; "manifest.json" is the
	// other convention in wide use. Both are matched as the whole final
	// segment, so "manifest.json.php" and "app.webmanifest.bak" are not.
	return strings.HasSuffix(name, ".webmanifest") || name == "manifest.json"
}
