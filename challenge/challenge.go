// Package challenge implements a JavaScript proof-of-work challenge that
// filters low-sophistication bots (curl, scrapers) while letting real browsers
// pass with a signed bypass cookie. The PoW difficulty is intentionally light
// (first byte of SHA-256 == 0, ~256 attempts on average) so real browsers
// solve it in well under a second.
package challenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed page.html
var pageHTML string

// fpJS is the vendored FingerprintJS v5 IIFE bundle (MIT — see
// THIRD_PARTY_NOTICES.md), served at /_cz/fp.js and loaded by the challenge
// page to compute a browser visitor ID alongside the PoW. Vendored rather
// than loaded from openfpcdn.io because ad blockers and Brave/Firefox block
// the public CDN, which would silently disable visitor tracking.
//
//go:embed fp.min.js
var fpJS []byte

var pageTmpl = template.Must(template.New("challenge").Parse(pageHTML))

const cookieName = "cz_bot_ok"

// visitorIDPattern matches FingerprintJS visitor IDs (32-char hex today;
// allow a little slack but nothing that could break the cookie format).
var visitorIDPattern = regexp.MustCompile(`^[0-9a-zA-Z]{8,64}$`)

// sanitizeVisitorID returns id if it looks like a FingerprintJS visitor ID,
// "" otherwise — never trust a client-supplied string into a cookie verbatim.
func sanitizeVisitorID(id string) string {
	if visitorIDPattern.MatchString(id) {
		return id
	}
	return ""
}

// usedNonceSweepAt is the map size past which redeemed-nonce bookkeeping is
// swept of expired entries on insert. Entries only enter the map on a
// signature-valid solve and expire within the 2-minute challenge window, so
// this is a tidiness bound, not a hard cap.
const usedNonceSweepAt = 4096

// Challenger generates, verifies, and cookie-guards JS PoW challenges.
type Challenger struct {
	secret    string
	ttl       int // cookie lifetime in seconds
	threshold int // anomaly score that triggers a challenge

	mu   sync.Mutex
	used map[string]int64 // redeemed nonce → its exp; enforces single use
}

// New creates a Challenger.
//   - secret: HMAC key; must be stable across restarts (stored in DB).
//   - ttlSeconds: how long the bypass cookie is valid (default 3600 = 1h).
//   - threshold: bot anomaly score at which a challenge is issued.
func New(secret string, ttlSeconds, threshold int) *Challenger {
	return &Challenger{secret: secret, ttl: ttlSeconds, threshold: threshold, used: make(map[string]int64)}
}

// markNonceUsed records a fully validated solve, returning false when the
// nonce was already redeemed — a captured (nonce, exp, sig, solution) tuple
// must not mint more than one bypass cookie within its 2-minute window.
// Only signature-valid nonces ever reach this map, so it grows at the rate
// of genuine solves and is swept of expired entries once it gets large.
func (c *Challenger) markNonceUsed(nonce string, exp int64) bool {
	now := time.Now().Unix()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.used) >= usedNonceSweepAt {
		for n, e := range c.used {
			if now > e {
				delete(c.used, n)
			}
		}
	}
	if _, dup := c.used[nonce]; dup {
		return false
	}
	c.used[nonce] = exp
	return true
}

// Threshold returns the anomaly score at which a challenge is triggered.
func (c *Challenger) Threshold() int { return c.threshold }

// PassedChallenge returns true if the request carries a valid, unexpired
// bypass cookie issued by a previous successful challenge solve.
func (c *Challenger) PassedChallenge(r *http.Request) bool {
	ck, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	_, ok := c.parseCookie(ck.Value)
	return ok
}

// VisitorID returns the FingerprintJS visitor ID bound into the request's
// bypass cookie, or "" when there is no valid cookie or the challenge was
// solved without a fingerprint. The value is covered by the cookie HMAC, so
// a client can't swap in someone else's ID without invalidating the cookie.
func (c *Challenger) VisitorID(r *http.Request) string {
	ck, err := r.Cookie(cookieName)
	if err != nil {
		return ""
	}
	vid, _ := c.parseCookie(ck.Value)
	return vid
}

// ServeFingerprintJS serves the vendored FingerprintJS bundle. Handles
// GET /_cz/fp.js. Cacheable: the bundle only changes with a binary upgrade.
func (c *Challenger) ServeFingerprintJS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(fpJS) //nolint:errcheck
}

// ChallengeURL builds the redirect destination for the challenge page.
// originalPath is where the browser should land after a successful solve.
// The URL embeds a signed nonce so the verify endpoint can authenticate it.
func (c *Challenger) ChallengeURL(originalPath string) string {
	b := make([]byte, 16)
	rand.Read(b)
	nonce := hex.EncodeToString(b)
	expiry := time.Now().Unix() + 120 // 2-minute window to solve
	sig := c.signNonce(nonce, expiry)
	return fmt.Sprintf("/_cz/challenge?n=%s&r=%s&exp=%d&sig=%s",
		nonce, url.QueryEscape(originalPath), expiry, sig)
}

// ServePage renders the JS PoW challenge HTML. Handles GET /_cz/challenge.
func (c *Challenger) ServePage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	nonce := q.Get("n")
	redir := q.Get("r")
	expStr := q.Get("exp")
	sig := q.Get("sig")

	expiry, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || nonce == "" || time.Now().Unix() > expiry {
		http.Error(w, "invalid or expired challenge", http.StatusBadRequest)
		return
	}
	if !hmac.Equal([]byte(sig), []byte(c.signNonce(nonce, expiry))) {
		http.Error(w, "invalid challenge", http.StatusForbidden)
		return
	}

	// Embed all values as a single JSON object so html/template handles
	// escaping uniformly rather than per-field.
	cfg, _ := json.Marshal(map[string]any{
		"nonce":    nonce,
		"exp":      expiry,
		"sig":      sig,
		"redirect": redir,
	})

	// Reference ID shown in the page footer (like Cloudflare's Ray ID):
	// the nonce prefix is enough to find the solve attempt in support cases.
	refID := nonce
	if len(refID) > 12 {
		refID = refID[:12]
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	pageTmpl.Execute(w, map[string]any{ //nolint:errcheck
		"ConfigJSON": template.JS(cfg),
		"Host":       r.Host,
		"RefID":      refID,
	})
}

// verifyRequest is the JSON body expected by POST /_cz/verify.
type verifyRequest struct {
	Nonce    string `json:"nonce"`
	Exp      int64  `json:"exp"`
	Sig      string `json:"sig"`
	Solution uint64 `json:"solution"`
	// VisitorID is the FingerprintJS browser fingerprint, "" when the
	// library failed/was blocked. Optional: the PoW alone passes the
	// challenge; the fingerprint only enriches logging.
	VisitorID string `json:"visitor_id"`
	// Automation is the list of automated-browser leakage signals the
	// challenge page detected (navigator.webdriver, ChromeDriver cdc_ arrays,
	// Selenium/Puppeteer/Playwright globals, HeadlessChrome UA, ...). A real
	// browser reports none of these; any recognized signal means we refuse
	// the bypass cookie so the client stays challenged. See knownAutomationSignals.
	Automation []string `json:"automation"`
}

// knownAutomationSignals is the set of leakage tokens the challenge page can
// report. Only tokens in this set count toward a block — a client can't stuff
// arbitrary strings to influence the decision, and unknown tokens (from a
// newer/older page) are ignored rather than trusted. These artifacts do not
// exist in a genuine, human-driven browser, so any single one is decisive.
//
// This is client-side detection: a determined attacker who reads this JS can
// strip the signals before POSTing. It is not meant to stop that — it stops
// off-the-shelf browser-driven scanners (OWASP ZAP's Chrome mode, Selenium,
// Puppeteer, Playwright) that leak these markers by default, and it composes
// with the autoban scorer: a client we refuse loops the challenge and is
// eventually IP-banned for the repeated unsolved bot_challenge redirects.
var knownAutomationSignals = map[string]bool{
	"webdriver":     true, // navigator.webdriver === true (WebDriver spec flag)
	"cdc":           true, // ChromeDriver cdc_/$cdc_ injected arrays
	"domautomation": true, // window.domAutomation(Controller) — ChromeDriver
	"selenium":      true, // __selenium_*/__webdriver_* globals & attributes
	"phantom":       true, // PhantomJS _phantom/callPhantom/__phantomas
	"nightmare":     true, // Nightmare.js __nightmare
	"puppeteer":     true, // Puppeteer markers
	"playwright":    true, // Playwright __playwright/__pw_* globals
	"headless":      true, // HeadlessChrome in the User-Agent
}

// firstAutomationSignal returns the first recognized automation-leakage token
// in sigs, or "" if none are recognized. Unknown tokens are ignored.
func firstAutomationSignal(sigs []string) string {
	for _, s := range sigs {
		if knownAutomationSignals[s] {
			return s
		}
	}
	return ""
}

// ServeVerify handles POST /_cz/verify: authenticates the token, checks the
// PoW solution, and issues a bypass cookie on success.
func (c *Challenger) ServeVerify(w http.ResponseWriter, r *http.Request) {
	// This endpoint is reachable unauthenticated — cap the body so a giant
	// JSON string can't balloon memory. A real verify payload is <1 KiB.
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Nonce == "" || time.Now().Unix() > req.Exp {
		http.Error(w, "expired", http.StatusForbidden)
		return
	}
	if !hmac.Equal([]byte(req.Sig), []byte(c.signNonce(req.Nonce, req.Exp))) {
		http.Error(w, "invalid signature", http.StatusForbidden)
		return
	}
	if !verifyPoW(req.Nonce, req.Solution) {
		http.Error(w, "incorrect solution", http.StatusForbidden)
		return
	}
	// Automated-browser gate: a valid PoW solution only proves the client can
	// run JavaScript, which headless Chrome / Selenium / Puppeteer all do. If
	// the page reported any automation-leakage signal, refuse the bypass cookie
	// so the client keeps hitting the challenge (and accrues autoban points)
	// instead of being trusted for high-velocity scraping.
	if sig := firstAutomationSignal(req.Automation); sig != "" {
		http.Error(w, "automation detected", http.StatusForbidden)
		return
	}
	// Last check, so a solve rejected above doesn't burn its nonce: each
	// nonce redeems exactly one cookie — replaying a captured solution
	// within its 2-minute validity gets a 403 instead of a second cookie.
	if !c.markNonceUsed(req.Nonce, req.Exp) {
		http.Error(w, "challenge already used", http.StatusForbidden)
		return
	}
	c.issueCookie(w, r, sanitizeVisitorID(req.VisitorID))
	w.WriteHeader(http.StatusOK)
}

// ── internal helpers ────────────────────────────────────────────────────────

// verifyPoW checks that SHA-256(nonce + decimal(solution))[0] == 0x00.
func verifyPoW(nonce string, solution uint64) bool {
	h := sha256.Sum256([]byte(nonce + strconv.FormatUint(solution, 10)))
	return h[0] == 0x00
}

// secureRequest reports whether the bypass cookie should carry the Secure
// flag: the request arrived over TLS directly or, behind a TLS-terminating
// proxy, via X-Forwarded-Proto (spoofing that header can only *add* the
// flag, which locks the spoofer out of plain HTTP — never the reverse).
// Same rule as the admin UI's secureCookie.
func secureRequest(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (c *Challenger) issueCookie(w http.ResponseWriter, r *http.Request, visitorID string) {
	expiry := time.Now().Unix() + int64(c.ttl)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    c.buildCookieValue(expiry, visitorID),
		Path:     "/",
		Expires:  time.Unix(expiry, 0),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secureRequest(r),
	})
}

// buildCookieValue produces "expiry.visitorID.sig" with the visitor ID inside
// the HMAC input, so the fingerprint travels with every request tamper-evident
// and without any server-side session state. visitorID may be "".
func (c *Challenger) buildCookieValue(expiry int64, visitorID string) string {
	mac := hmac.New(sha256.New, []byte(c.secret))
	fmt.Fprintf(mac, "cz-pass:%d:%s", expiry, visitorID)
	return fmt.Sprintf("%d.%s.%s", expiry, visitorID, hex.EncodeToString(mac.Sum(nil)[:16]))
}

// parseCookie validates a bypass cookie and returns the visitor ID bound into
// it. Accepts the current "expiry.visitorID.sig" format and the legacy
// pre-fingerprint "expiry.sig" format (no visitor ID), so cookies issued
// before an upgrade stay valid until they expire.
func (c *Challenger) parseCookie(value string) (visitorID string, ok bool) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 && len(parts) != 3 {
		return "", false
	}
	expiry, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() > expiry {
		return "", false
	}

	mac := hmac.New(sha256.New, []byte(c.secret))
	sig := parts[1]
	if len(parts) == 3 {
		visitorID = parts[1]
		sig = parts[2]
		fmt.Fprintf(mac, "cz-pass:%d:%s", expiry, visitorID)
	} else {
		fmt.Fprintf(mac, "cz-pass:%d", expiry)
	}
	expected := hex.EncodeToString(mac.Sum(nil)[:16])
	if !hmac.Equal([]byte(expected), []byte(sig)) {
		return "", false
	}
	return visitorID, true
}

func (c *Challenger) signNonce(nonce string, expiry int64) string {
	mac := hmac.New(sha256.New, []byte(c.secret))
	fmt.Fprintf(mac, "cz-nonce:%s:%d", nonce, expiry)
	return hex.EncodeToString(mac.Sum(nil)[:16])
}
