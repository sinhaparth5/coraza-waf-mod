package storage

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// TestSecretEncryptionMigratesAndRoundTrips pins the whole lifecycle: a
// deployment writes secrets plaintext, an admin later configures a key, and
// EnableSecretEncryption seals everything in place while the public getters
// keep returning the original values. New writes while a key is active must
// land sealed too.
func TestSecretEncryptionMigratesAndRoundTrips(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Plaintext era: write one of each secret kind.
	if err := db.SetEmailConfig(EmailConfig{Enabled: true, Token: "cf-token", To: "a@b.c"}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetRedisConfig("127.0.0.1:6379", "redis-pw"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetWebhookConfig(WebhookConfig{URL: "https://x", Secret: "hook-secret", Enabled: true, Events: "blocked"}); err != nil {
		t.Fatal(err)
	}
	challenge, err := db.GetOrCreateChallengeSecret()
	if err != nil || challenge == "" {
		t.Fatalf("challenge secret: %q, %v", challenge, err)
	}
	if raw, _ := db.getMeta("email_token"); raw != "cf-token" {
		t.Fatalf("pre-key email_token stored as %q, want plaintext", raw)
	}

	key := bytes.Repeat([]byte{7}, 32)
	if err := db.EnableSecretEncryption(key); err != nil {
		t.Fatal(err)
	}

	// Migration must have sealed every stored secret...
	for _, metaKey := range []string{"email_token", "redis_password", "challenge_secret"} {
		raw, err := db.getMeta(metaKey)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(raw, secretPrefix) {
			t.Errorf("%s not sealed after migration: %q", metaKey, raw)
		}
	}
	var rawHook string
	if err := db.conn.QueryRow(`SELECT secret FROM webhook_config WHERE id = 1`).Scan(&rawHook); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rawHook, secretPrefix) {
		t.Errorf("webhook secret not sealed after migration: %q", rawHook)
	}

	// ...while the getters still return the original plaintext.
	if cfg, err := db.GetEmailConfig(); err != nil || cfg.Token != "cf-token" {
		t.Errorf("GetEmailConfig = %+v, %v; want Token=cf-token", cfg, err)
	}
	if _, pw, err := db.GetRedisConfig(); err != nil || pw != "redis-pw" {
		t.Errorf("GetRedisConfig password = %q, %v; want redis-pw", pw, err)
	}
	if cfg, err := db.GetWebhookConfig(); err != nil || cfg.Secret != "hook-secret" {
		t.Errorf("GetWebhookConfig = %+v, %v; want Secret=hook-secret", cfg, err)
	}
	if got, err := db.GetOrCreateChallengeSecret(); err != nil || got != challenge {
		t.Errorf("challenge secret after migration = %q, %v; want the original %q", got, err, challenge)
	}

	// Writes under an active key: the TOTP enrollment flow end to end.
	if err := db.SetPendingTOTPSecret("JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatal(err)
	}
	if raw, _ := db.getMeta("admin_totp_pending_secret"); !strings.HasPrefix(raw, secretPrefix) {
		t.Errorf("pending TOTP secret written plaintext under active key: %q", raw)
	}
	if err := db.EnableTOTP([]string{"hash1", "hash2"}); err != nil {
		t.Fatal(err)
	}
	if got, err := db.GetTOTPSecret(); err != nil || got != "JBSWY3DPEHPK3PXP" {
		t.Errorf("GetTOTPSecret = %q, %v; want the enrolled secret", got, err)
	}
	if enabled, err := db.TOTPEnabled(); err != nil || !enabled {
		t.Errorf("TOTPEnabled = %v, %v; want true", enabled, err)
	}
}

// TestSecretEncryptionKeyErrors pins the failure modes: sealed values read
// without a key, or with the wrong key, must fail loudly — never come back
// as empty config, and (for the challenge secret) never be silently
// regenerated, which would invalidate every outstanding bypass cookie while
// hiding the misconfiguration.
func TestSecretEncryptionKeyErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.EnableSecretEncryption(bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatal(err)
	}
	if err := db.SetEmailConfig(EmailConfig{Token: "cf-token"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetOrCreateChallengeSecret(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen with no key at all.
	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetEmailConfig(); err == nil || !strings.Contains(err.Error(), "db-key-file") {
		t.Errorf("no-key read error = %v; want a --db-key-file hint", err)
	}
	if _, err := db.GetOrCreateChallengeSecret(); err == nil {
		t.Error("no-key challenge secret read succeeded; must error, not regenerate")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen with the wrong key: migration must leave the sealed values
	// untouched (they're already prefixed) and reads must fail on decrypt.
	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.EnableSecretEncryption(bytes.Repeat([]byte{2}, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetEmailConfig(); err == nil {
		t.Error("wrong-key read succeeded; want decrypt error")
	}

	if err := db.EnableSecretEncryption([]byte("short")); err == nil {
		t.Error("EnableSecretEncryption accepted a non-32-byte key")
	}
}
