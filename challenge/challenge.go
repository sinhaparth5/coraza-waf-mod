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
	"strconv"
	"strings"
	"time"
)

//go:embed page.html
var pageHTML string

var pageTmpl = template.Must(template.New("challenge").Parse(pageHTML))

const cookieName = "cz_bot_ok"

// Challenger generates, verifies, and cookie-guards JS PoW challenges.
type Challenger struct {
	secret    string
	ttl       int // cookie lifetime in seconds
	threshold int // anomaly score that triggers a challenge
}

// New creates a Challenger.
//   - secret: HMAC key; must be stable across restarts (stored in DB).
//   - ttlSeconds: how long the bypass cookie is valid (default 3600 = 1h).
//   - threshold: bot anomaly score at which a challenge is issued.
func New(secret string, ttlSeconds, threshold int) *Challenger {
	return &Challenger{secret: secret, ttl: ttlSeconds, threshold: threshold}
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
	return c.verifyCookie(ck.Value)
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

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	pageTmpl.Execute(w, map[string]any{ //nolint:errcheck
		"ConfigJSON": template.JS(cfg),
	})
}

// verifyRequest is the JSON body expected by POST /_cz/verify.
type verifyRequest struct {
	Nonce    string `json:"nonce"`
	Exp      int64  `json:"exp"`
	Sig      string `json:"sig"`
	Solution uint64 `json:"solution"`
}

// ServeVerify handles POST /_cz/verify: authenticates the token, checks the
// PoW solution, and issues a bypass cookie on success.
func (c *Challenger) ServeVerify(w http.ResponseWriter, r *http.Request) {
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
	c.issueCookie(w)
	w.WriteHeader(http.StatusOK)
}

// GenerateSecret returns a cryptographically random 64-char hex secret
// suitable for use as the HMAC key.
func GenerateSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ── internal helpers ────────────────────────────────────────────────────────

// verifyPoW checks that SHA-256(nonce + decimal(solution))[0] == 0x00.
func verifyPoW(nonce string, solution uint64) bool {
	h := sha256.Sum256([]byte(nonce + strconv.FormatUint(solution, 10)))
	return h[0] == 0x00
}

func (c *Challenger) issueCookie(w http.ResponseWriter) {
	expiry := time.Now().Unix() + int64(c.ttl)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    c.buildCookieValue(expiry),
		Path:     "/",
		Expires:  time.Unix(expiry, 0),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (c *Challenger) buildCookieValue(expiry int64) string {
	mac := hmac.New(sha256.New, []byte(c.secret))
	fmt.Fprintf(mac, "cz-pass:%d", expiry)
	return fmt.Sprintf("%d.%s", expiry, hex.EncodeToString(mac.Sum(nil)[:16]))
}

func (c *Challenger) verifyCookie(value string) bool {
	parts := strings.SplitN(value, ".", 2)
	if len(parts) != 2 {
		return false
	}
	expiry, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() > expiry {
		return false
	}
	mac := hmac.New(sha256.New, []byte(c.secret))
	fmt.Fprintf(mac, "cz-pass:%d", expiry)
	expected := hex.EncodeToString(mac.Sum(nil)[:16])
	return hmac.Equal([]byte(expected), []byte(parts[1]))
}

func (c *Challenger) signNonce(nonce string, expiry int64) string {
	mac := hmac.New(sha256.New, []byte(c.secret))
	fmt.Fprintf(mac, "cz-nonce:%s:%d", nonce, expiry)
	return hex.EncodeToString(mac.Sum(nil)[:16])
}
