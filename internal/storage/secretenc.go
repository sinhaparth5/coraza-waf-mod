package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"
)

// Secrets-at-rest encryption (opt-in via the server's --db-key-file flag).
//
// A SQLite file is plaintext: anyone who exfiltrates waf.db (or a Settings
// backup, which is a byte-for-byte VACUUM INTO copy) can read every stored
// value. Most of the DB is fine that way — request logs, IP rules, service
// routes — but a handful of values are live, directly usable credentials:
// the challenge-cookie HMAC secret (forge bot-bypass cookies), the TOTP
// secrets (defeat admin 2FA), the Cloudflare email token, the Redis password,
// and the webhook X-WAF-Secret header value. Those, and only those, are
// sealed with AES-256-GCM when a key is configured. Values already safe at
// rest stay as they are: the admin password is bcrypt-hashed, API keys and
// TOTP backup codes are SHA-256 digests of high-entropy tokens.
//
// The stored form is "enc:v1:" + base64(nonce || ciphertext). Reads are
// format-dispatched, not mode-dispatched: a value without the prefix is
// returned verbatim (legacy plaintext keeps working with or without a key),
// and a value with the prefix requires the key (missing/wrong key is a loud
// error, never silently-empty config). EnableSecretEncryption migrates any
// still-plaintext secrets in place, so turning the flag on for an existing
// deployment needs no manual step — and turning it off again only breaks the
// values written while it was on, with an error that says why.

// secretPrefix marks a stored value as sealed. Versioned so a future cipher
// change can coexist with v1 values instead of requiring a migration flag day.
const secretPrefix = "enc:v1:"

// secretMetaKeys is every meta key holding a live secret. Extend this list
// (and nothing else) when a new secret-bearing meta key is added — the
// getters/setters for these must go through getSecretMeta/setSecretMeta.
// The webhook secret lives in the webhook_config table, not meta, and is
// handled separately in migrateSecrets/Get/SetWebhookConfig.
var secretMetaKeys = []string{
	"challenge_secret",
	"admin_totp_secret",
	"admin_totp_pending_secret",
	"redis_password",
	"email_token",
}

// EnableSecretEncryption switches the DB into secrets-at-rest mode with a
// 32-byte AES-256 key, then re-writes any still-plaintext secrets sealed.
// Call once, right after Open and before anything reads secret config.
func (db *DB) EnableSecretEncryption(key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("secret encryption key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	db.secretGCM = gcm
	return db.migrateSecrets()
}

// sealSecret encrypts a value for storage. Without a key (or for the empty
// string, which encodes "unset" throughout the meta table) it is the
// identity function, so every caller can seal unconditionally.
func (db *DB) sealSecret(plain string) (string, error) {
	if db.secretGCM == nil || plain == "" {
		return plain, nil
	}
	nonce := make([]byte, db.secretGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("seal secret: %w", err)
	}
	sealed := db.secretGCM.Seal(nonce, nonce, []byte(plain), nil)
	return secretPrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// openSecret reverses sealSecret. Unprefixed values pass through verbatim —
// that's what keeps plaintext deployments and pre-migration values working.
func (db *DB) openSecret(stored string) (string, error) {
	if !strings.HasPrefix(stored, secretPrefix) {
		return stored, nil
	}
	if db.secretGCM == nil {
		return "", fmt.Errorf("value is encrypted at rest but no --db-key-file was provided")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, secretPrefix))
	if err != nil {
		return "", fmt.Errorf("decode encrypted secret: %w", err)
	}
	ns := db.secretGCM.NonceSize()
	if len(raw) < ns {
		return "", fmt.Errorf("encrypted secret too short to hold a nonce")
	}
	plain, err := db.secretGCM.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("decrypt secret (wrong --db-key-file?): %w", err)
	}
	return string(plain), nil
}

// getSecretMeta / setSecretMeta are the secret-bearing twins of
// getMeta/setMeta; the keys in secretMetaKeys must only be accessed through
// these so a value is never accidentally written plaintext while a key is
// active.
func (db *DB) getSecretMeta(key string) (string, error) {
	v, err := db.getMeta(key)
	if err != nil || v == "" {
		return v, err
	}
	plain, err := db.openSecret(v)
	if err != nil {
		return "", fmt.Errorf("%s: %w", key, err)
	}
	return plain, nil
}

func (db *DB) setSecretMeta(key, value string) error {
	sealed, err := db.sealSecret(value)
	if err != nil {
		return err
	}
	return db.setMeta(key, sealed)
}

// migrateSecrets seals any secret still stored plaintext — the transparent
// upgrade path for deployments that existed before a key was configured.
// Already-sealed values are left alone (also what makes running with a
// *different* key fail at read time rather than corrupting them here).
func (db *DB) migrateSecrets() error {
	for _, key := range secretMetaKeys {
		v, err := db.getMeta(key)
		if err != nil {
			return err
		}
		if v == "" || strings.HasPrefix(v, secretPrefix) {
			continue
		}
		sealed, err := db.sealSecret(v)
		if err != nil {
			return err
		}
		if err := db.setMeta(key, sealed); err != nil {
			return err
		}
	}

	var secret string
	err := db.conn.QueryRow(`SELECT secret FROM webhook_config WHERE id = 1`).Scan(&secret)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	if secret == "" || strings.HasPrefix(secret, secretPrefix) {
		return nil
	}
	sealed, err := db.sealSecret(secret)
	if err != nil {
		return err
	}
	_, err = db.conn.Exec(`UPDATE webhook_config SET secret=? WHERE id=1`, sealed)
	return err
}
