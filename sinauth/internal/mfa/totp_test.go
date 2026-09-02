package mfa

import (
	"encoding/base32"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// TestRFC6238Vectors validates that sinauth's TOTP dependency
// (github.com/pquerna/otp) produces the standard RFC 6238 Appendix B test
// vectors: SHA1, 8-digit codes, secret "12345678901234567890" (ASCII),
// T0=0, X=30. This proves the library integration is spec-correct — the
// codebase never hand-rolls HOTP/TOTP math (per this repo's crypto policy)
// so what's under test here is "did we wire the library up right," not a
// reimplementation of the algorithm.
func TestRFC6238Vectors(t *testing.T) {
	const secretASCII = "12345678901234567890"
	secret := base32Encode(secretASCII)

	vectors := []struct {
		t    int64
		code string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
	}

	for _, v := range vectors {
		got, err := totp.GenerateCodeCustom(secret, time.Unix(v.t, 0), totp.ValidateOpts{
			Period:    30,
			Digits:    otp.DigitsEight,
			Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil {
			t.Fatalf("GenerateCodeCustom(t=%d): %v", v.t, err)
		}
		if got != v.code {
			t.Errorf("t=%d: got code %s, want %s", v.t, got, v.code)
		}
	}
}

// base32Encode mirrors how pquerna/otp expects secrets to be provided to
// GenerateCodeCustom/ValidateCustom (base32, no padding) — the RFC 6238
// vectors give the shared secret as raw ASCII bytes.
func base32Encode(asciiSecret string) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(asciiSecret))
}

// TestValidateTOTPCode_RoundTrip proves our wrapper (validateTOTPCode, using
// this file's fixed period/digits/algorithm/skew configuration) actually
// accepts a code generated with the exact same parameters for "now" — i.e.
// enrollment and login-time verification agree on the same TOTP parameters.
func TestValidateTOTPCode_RoundTrip(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: "roundtrip@example.com",
		Period:      totpPeriod,
		Digits:      totpDigits,
		Algorithm:   totpAlgo,
	})
	if err != nil {
		t.Fatalf("totp.Generate: %v", err)
	}

	code, err := totp.GenerateCodeCustom(key.Secret(), time.Now(), totp.ValidateOpts{
		Period:    totpPeriod,
		Digits:    totpDigits,
		Algorithm: totpAlgo,
	})
	if err != nil {
		t.Fatalf("GenerateCodeCustom: %v", err)
	}

	if !validateTOTPCode(key.Secret(), code) {
		t.Fatal("validateTOTPCode: expected true for a code generated with matching secret/time/params")
	}
}

func TestValidateTOTPCode_WrongCodeRejected(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: "wrongcode@example.com",
		Period:      totpPeriod,
		Digits:      totpDigits,
		Algorithm:   totpAlgo,
	})
	if err != nil {
		t.Fatalf("totp.Generate: %v", err)
	}

	if validateTOTPCode(key.Secret(), "000000") {
		// Astronomically unlikely to collide, but guard against the flake by
		// only failing if 000000 is genuinely wrong (it always will be for a
		// freshly random secret in practice).
		t.Fatal("validateTOTPCode: expected false for an arbitrary wrong code")
	}
}

func TestValidateTOTPCode_EmptyRejected(t *testing.T) {
	if validateTOTPCode("JBSWY3DPEHPK3PXP", "") {
		t.Fatal("validateTOTPCode: expected false for empty code")
	}
	if validateTOTPCode("JBSWY3DPEHPK3PXP", "   ") {
		t.Fatal("validateTOTPCode: expected false for whitespace-only code")
	}
}

// TestValidateTOTPCode_SkewAllowsAdjacentPeriod proves the configured skew
// (±1 period) accepts a code from one time-step away — the deliberate,
// narrow clock-skew allowance this file documents, not an "anything goes"
// window.
func TestValidateTOTPCode_SkewAllowsAdjacentPeriod(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: "skew@example.com",
		Period:      totpPeriod,
		Digits:      totpDigits,
		Algorithm:   totpAlgo,
	})
	if err != nil {
		t.Fatalf("totp.Generate: %v", err)
	}

	oneStepAgo := time.Now().Add(-totpPeriod * time.Second)
	code, err := totp.GenerateCodeCustom(key.Secret(), oneStepAgo, totp.ValidateOpts{
		Period:    totpPeriod,
		Digits:    totpDigits,
		Algorithm: totpAlgo,
	})
	if err != nil {
		t.Fatalf("GenerateCodeCustom: %v", err)
	}

	if !validateTOTPCode(key.Secret(), code) {
		t.Fatal("validateTOTPCode: expected true for a code one period old, within the configured skew")
	}
}

// TestValidateTOTPCode_FarOutsideSkewRejected proves the skew window is
// actually bounded — a code from many periods away must not validate.
func TestValidateTOTPCode_FarOutsideSkewRejected(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: "farskew@example.com",
		Period:      totpPeriod,
		Digits:      totpDigits,
		Algorithm:   totpAlgo,
	})
	if err != nil {
		t.Fatalf("totp.Generate: %v", err)
	}

	farAway := time.Now().Add(-1 * time.Hour)
	code, err := totp.GenerateCodeCustom(key.Secret(), farAway, totp.ValidateOpts{
		Period:    totpPeriod,
		Digits:    totpDigits,
		Algorithm: totpAlgo,
	})
	if err != nil {
		t.Fatalf("GenerateCodeCustom: %v", err)
	}

	if validateTOTPCode(key.Secret(), code) {
		t.Fatal("validateTOTPCode: expected false for a code from an hour ago, well outside the ±1 period skew")
	}
}

// ── backup codes ─────────────────────────────────────────────────────────

func TestGenerateBackupCodes_CountAndFormat(t *testing.T) {
	plain, hashes, err := generateBackupCodes(4) // low bcrypt cost for test speed
	if err != nil {
		t.Fatalf("generateBackupCodes: %v", err)
	}
	if len(plain) != numBackupCodes || len(hashes) != numBackupCodes {
		t.Fatalf("got %d plain / %d hashes, want %d each", len(plain), len(hashes), numBackupCodes)
	}

	seen := map[string]bool{}
	for _, c := range plain {
		if len(c) != 9 || c[4] != '-' {
			t.Errorf("backup code %q does not match expected XXXX-XXXX format", c)
		}
		if seen[c] {
			t.Errorf("duplicate backup code generated: %q", c)
		}
		seen[c] = true
	}
}

func TestGenerateBackupCodes_HashVerifiesCanonicalForm(t *testing.T) {
	plain, hashes, err := generateBackupCodes(4)
	if err != nil {
		t.Fatalf("generateBackupCodes: %v", err)
	}
	// Each hash must verify against the canonical form of its own plaintext
	// code — this is the same check VerifyTOTPBackupCode performs.
	for i, code := range plain {
		canon := canonicalizeBackupCode(code)
		if err := bcrypt.CompareHashAndPassword([]byte(hashes[i]), []byte(canon)); err != nil {
			t.Errorf("backup code %d: hash does not verify against its own canonical plaintext: %v", i, err)
		}
	}
}

func TestCanonicalizeBackupCode(t *testing.T) {
	cases := []struct{ in, want string }{
		{"abcd-1234", "ABCD1234"},
		{"ABCD-1234", "ABCD1234"},
		{" abcd - 1234 ", "ABCD1234"},
		{"abcd1234", "ABCD1234"},
	}
	for _, c := range cases {
		if got := canonicalizeBackupCode(c.in); got != c.want {
			t.Errorf("canonicalizeBackupCode(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
