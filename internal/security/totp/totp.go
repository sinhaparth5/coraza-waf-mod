// Package totp implements RFC 6238 time-based one-time passwords (on top
// of RFC 4226 HOTP) for the admin login's second factor. Pure Go, no
// external service: the shared secret lives in the DB, codes are computed
// locally by both sides, so the single-binary design keeps working offline.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // SHA-1 is what RFC 6238 specifies and what authenticator apps implement
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// step is the TOTP time step. 30s is the RFC default and what every
	// authenticator app assumes when the otpauth:// URI doesn't say otherwise.
	step = 30 * time.Second
	// digits is the code length. 6 is the app default; 8 buys little here
	// because the login limiter already throttles guessing per IP.
	digits = 6
	// skew is how many time steps either side of "now" Validate accepts,
	// covering clock drift between this server and the admin's phone.
	skew = 1
)

// b32 is unpadded uppercase base32, the alphabet authenticator apps expect
// for manual secret entry.
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecret returns a new random 160-bit secret, base32-encoded for
// direct use in an otpauth:// URI or manual entry.
func GenerateSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

// hotp computes the RFC 4226 code for one counter value.
func hotp(key []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", digits, code%1_000_000)
}

// decodeSecret is tolerant of the ways humans re-enter a secret: lowercase,
// spaces, and padding are all accepted.
func decodeSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	s = strings.TrimRight(s, "=")
	return b32.DecodeString(s)
}

// Counter returns the TOTP counter (time step index) for t.
func Counter(t time.Time) uint64 {
	return uint64(t.Unix() / int64(step.Seconds()))
}

// Code returns the code valid at t. Used by tests and by the enrollment
// confirm step; Validate is what login should call.
func Code(secret string, t time.Time) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	return hotp(key, Counter(t)), nil
}

// Validate reports whether code is correct for secret at time t, checking
// the current step plus ±skew for clock drift. On success it also returns
// the matched counter so the caller can persist it and reject replays: a
// TOTP code is otherwise valid for the whole 30s window, so a shoulder-surfed
// or intercepted code could be reused within it. Comparison is constant-time
// per candidate; every candidate is always evaluated so a match doesn't
// return early.
func Validate(secret, code string, t time.Time) (ok bool, counter uint64) {
	key, err := decodeSecret(secret)
	if err != nil {
		return false, 0
	}
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	base := Counter(t)
	for i := -skew; i <= skew; i++ {
		c := uint64(int64(base) + int64(i))
		if subtle.ConstantTimeCompare([]byte(hotp(key, c)), []byte(code)) == 1 && !ok {
			ok, counter = true, c
		}
	}
	return ok, counter
}

// ProvisioningURI builds the otpauth:// URI encoded into the enrollment QR
// code, per the de-facto Key Uri Format (Google Authenticator wiki).
func ProvisioningURI(secret, account, issuer string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(digits))
	q.Set("period", fmt.Sprint(int(step.Seconds())))
	return "otpauth://totp/" + label + "?" + q.Encode()
}
