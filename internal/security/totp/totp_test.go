package totp

import (
	"strings"
	"testing"
	"time"
)

// rfcSecret is the RFC 6238 appendix B SHA-1 seed, ASCII
// "12345678901234567890", base32-encoded.
const rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

// TestCodeRFC6238Vectors checks Code against the RFC 6238 appendix B SHA-1
// test vectors. The RFC lists 8-digit codes; the 6-digit code is the same
// truncated value mod 10^6, i.e. the vector's last six digits.
func TestCodeRFC6238Vectors(t *testing.T) {
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}
	for _, tc := range cases {
		got, err := Code(rfcSecret, time.Unix(tc.unix, 0))
		if err != nil {
			t.Fatalf("Code(t=%d): %v", tc.unix, err)
		}
		if got != tc.want {
			t.Errorf("Code(t=%d) = %s, want %s", tc.unix, got, tc.want)
		}
	}
}

func TestValidateAcceptsSkewAndReturnsCounter(t *testing.T) {
	now := time.Unix(1111111111, 0)
	cases := []struct {
		name    string
		codeAt  time.Time
		wantOK  bool
		wantCtr uint64
	}{
		{"current step", now, true, Counter(now)},
		{"previous step (clock drift)", now.Add(-30 * time.Second), true, Counter(now) - 1},
		{"next step (clock drift)", now.Add(30 * time.Second), true, Counter(now) + 1},
		{"two steps back", now.Add(-60 * time.Second), false, 0},
		{"two steps ahead", now.Add(60 * time.Second), false, 0},
	}
	for _, tc := range cases {
		code, err := Code(rfcSecret, tc.codeAt)
		if err != nil {
			t.Fatal(err)
		}
		ok, ctr := Validate(rfcSecret, code, now)
		if ok != tc.wantOK {
			t.Errorf("%s: Validate = %v, want %v", tc.name, ok, tc.wantOK)
		}
		if ok && ctr != tc.wantCtr {
			t.Errorf("%s: counter = %d, want %d", tc.name, ctr, tc.wantCtr)
		}
	}
}

func TestValidateRejectsGarbage(t *testing.T) {
	now := time.Now()
	for _, code := range []string{"", "000000", "123456", "abcdef", "28708"} {
		// "000000"/"123456" could theoretically collide with the real code;
		// pick a fixed time where they're known not to.
		if ok, _ := Validate(rfcSecret, code, time.Unix(59, 0)); ok && code != "287082" {
			t.Errorf("Validate accepted %q", code)
		}
	}
	if ok, _ := Validate("not-base32!!", "287082", now); ok {
		t.Error("Validate accepted a code against an undecodable secret")
	}
}

func TestValidateToleratesSpacesAndCase(t *testing.T) {
	// Users paste codes with spaces ("287 082") and re-type secrets in
	// lowercase; both must still validate.
	if ok, _ := Validate(strings.ToLower(rfcSecret), " 287 082 ", time.Unix(59, 0)); !ok {
		t.Error("Validate rejected a spaced code / lowercase secret")
	}
}

func TestGenerateSecretShape(t *testing.T) {
	a, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("two generated secrets are identical")
	}
	// 20 bytes → 32 unpadded base32 chars.
	if len(a) != 32 {
		t.Errorf("secret length = %d, want 32", len(a))
	}
	if _, err := Code(a, time.Now()); err != nil {
		t.Errorf("generated secret does not round-trip through Code: %v", err)
	}
}

func TestProvisioningURI(t *testing.T) {
	uri := ProvisioningURI("ABC234", "admin@example.com", "Coraza WAF Mod")
	for _, want := range []string{
		"otpauth://totp/Coraza%20WAF%20Mod:admin@example.com?",
		"secret=ABC234",
		"issuer=Coraza+WAF+Mod",
		"digits=6",
		"period=30",
		"algorithm=SHA1",
	} {
		if !strings.Contains(uri, want) {
			t.Errorf("ProvisioningURI missing %q in %q", want, uri)
		}
	}
}
