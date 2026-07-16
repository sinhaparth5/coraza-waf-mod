package storage

import (
	"testing"
)

// TestTOTPEnrollmentLifecycle exercises the pending → enabled → disabled
// flow backing the 2FA settings card (ui/handlers.go).
func TestTOTPEnrollmentLifecycle(t *testing.T) {
	db := openTestDB(t)

	if enabled, _ := db.TOTPEnabled(); enabled {
		t.Fatal("TOTPEnabled = true on a fresh DB")
	}
	// Confirming with no enrollment pending must fail, not enable an empty secret.
	if err := db.EnableTOTP([]string{"h1"}); err == nil {
		t.Fatal("EnableTOTP with no pending secret must error")
	}

	if err := db.SetPendingTOTPSecret("SECRETBASE32"); err != nil {
		t.Fatal(err)
	}
	if enabled, _ := db.TOTPEnabled(); enabled {
		t.Fatal("a pending (unconfirmed) secret must not count as enabled")
	}
	if err := db.EnableTOTP([]string{"h1", "h2"}); err != nil {
		t.Fatal(err)
	}
	if secret, _ := db.GetTOTPSecret(); secret != "SECRETBASE32" {
		t.Fatalf("GetTOTPSecret = %q, want the promoted pending secret", secret)
	}
	if pending, _ := db.GetPendingTOTPSecret(); pending != "" {
		t.Fatalf("pending secret = %q after enable, want cleared", pending)
	}

	if err := db.DisableTOTP(); err != nil {
		t.Fatal(err)
	}
	if enabled, _ := db.TOTPEnabled(); enabled {
		t.Fatal("TOTPEnabled = true after DisableTOTP")
	}
	if used, _ := db.ConsumeTOTPBackupCode("h1"); used {
		t.Fatal("backup code survived DisableTOTP")
	}
}

// TestTOTPBackupCodesSingleUse checks each stored hash works exactly once
// and unknown hashes never match.
func TestTOTPBackupCodesSingleUse(t *testing.T) {
	db := openTestDB(t)

	if err := db.SetPendingTOTPSecret("S"); err != nil {
		t.Fatal(err)
	}
	if err := db.EnableTOTP([]string{"aaa", "bbb", "ccc"}); err != nil {
		t.Fatal(err)
	}

	if used, err := db.ConsumeTOTPBackupCode("bbb"); err != nil || !used {
		t.Fatalf("ConsumeTOTPBackupCode(bbb) = %v, %v, want true", used, err)
	}
	if used, _ := db.ConsumeTOTPBackupCode("bbb"); used {
		t.Fatal("backup code accepted twice")
	}
	if used, _ := db.ConsumeTOTPBackupCode("nope"); used {
		t.Fatal("unknown backup code accepted")
	}
	// The other two still work.
	for _, h := range []string{"aaa", "ccc"} {
		if used, _ := db.ConsumeTOTPBackupCode(h); !used {
			t.Fatalf("backup code %s no longer accepted after consuming a different one", h)
		}
	}
}

func TestTOTPLastCounterRoundtrip(t *testing.T) {
	db := openTestDB(t)

	if n, err := db.GetTOTPLastCounter(); err != nil || n != 0 {
		t.Fatalf("fresh GetTOTPLastCounter = %d, %v, want 0", n, err)
	}
	if err := db.SetTOTPLastCounter(59203941); err != nil {
		t.Fatal(err)
	}
	if n, _ := db.GetTOTPLastCounter(); n != 59203941 {
		t.Fatalf("GetTOTPLastCounter = %d, want 59203941", n)
	}
}
