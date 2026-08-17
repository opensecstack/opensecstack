package identity

import "testing"

func TestPattern_Regexp(t *testing.T) {
	// A regex-backed pattern must return its compiled regexp.
	regexPat := MustCompilePattern("test.regex.v1", CategoryWeakPassword, "d", "", 0.5, FieldPassword, `^\d+$`)
	if re := regexPat.Regexp(); re == nil {
		t.Fatal("Regexp() returned nil for a regex-backed pattern")
	} else if !re.MatchString("12345") {
		t.Fatalf("compiled regexp does not match expected input")
	}

	// A composite pattern (no regex) must return nil.
	compositePat := MustComposite("test.composite.v1", CategorySyntheticProfile, "d", "", 0.5)
	if re := compositePat.Regexp(); re != nil {
		t.Fatalf("Regexp() = %v, want nil for composite pattern", re)
	}
}

func TestMustCompilePattern_PanicsOnBadRegex(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on invalid regex")
		}
	}()
	MustCompilePattern("bad", CategoryWeakPassword, "d", "", 0.5, FieldPassword, `(unclosed`)
}

func TestIDFormatFor(t *testing.T) {
	cases := []struct {
		country string
		claim   ClaimType
		wantNil bool
	}{
		{"AL", ClaimPassport, false},
		{"al", ClaimPassport, false},   // case-insensitive
		{" AL ", ClaimPassport, false}, // trims whitespace
		{"AL", ClaimDriverLicense, false},
		{"ZZ", ClaimPassport, true},   // unknown country
		{"AL", ClaimLoginCreds, true}, // no rule for this claim type
	}
	for _, c := range cases {
		re := IDFormatFor(c.country, c.claim)
		if c.wantNil && re != nil {
			t.Errorf("IDFormatFor(%q, %q) = %v, want nil", c.country, c.claim, re)
		}
		if !c.wantNil && re == nil {
			t.Errorf("IDFormatFor(%q, %q) = nil, want non-nil", c.country, c.claim)
		}
	}

	// Verify the actual AL passport regex logic end-to-end.
	re := IDFormatFor("AL", ClaimPassport)
	if !re.MatchString("I1234567X") {
		t.Errorf("AL passport regex should match I1234567X")
	}
	if re.MatchString("bad-format") {
		t.Errorf("AL passport regex should not match bad-format")
	}
}

func TestIsSanctioned(t *testing.T) {
	cases := []struct {
		country string
		want    bool
	}{
		{"KP", true},
		{"IR", true},
		{"kp", true},   // case-insensitive
		{" IR ", true}, // trims
		{"US", false},
		{"AL", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsSanctioned(c.country); got != c.want {
			t.Errorf("IsSanctioned(%q) = %v, want %v", c.country, got, c.want)
		}
	}
}

func TestIsDisposableEmail(t *testing.T) {
	cases := []struct {
		email string
		want  bool
	}{
		{"a@mailinator.com", true},
		{"a@MAILINATOR.COM", true}, // case-insensitive host
		{"a@guerrillamail.com", true},
		{"a@gmail.com", false},
		{"no-at-sign", false},
		{"", false},
		{"@mailinator.com", true}, // empty local part still counts
	}
	for _, c := range cases {
		if got := IsDisposableEmail(c.email); got != c.want {
			t.Errorf("IsDisposableEmail(%q) = %v, want %v", c.email, got, c.want)
		}
	}
}

func TestIsLeakedHash(t *testing.T) {
	// SHA-1 of "password", uppercase per LeakedHashPrefixes convention.
	const passwordHash = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
	cases := []struct {
		hash string
		want bool
	}{
		{passwordHash, true},
		{"5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", true}, // case-insensitive
		{" " + passwordHash + " ", true},                   // trims whitespace
		{"0000000000000000000000000000000000000000", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsLeakedHash(c.hash); got != c.want {
			t.Errorf("IsLeakedHash(%q) = %v, want %v", c.hash, got, c.want)
		}
	}
}

func TestParseDOB(t *testing.T) {
	got := ParseDOB("1990-05-12")
	if got.IsZero() {
		t.Fatal("ParseDOB returned zero time for valid input")
	}
	if got.Year() != 1990 || int(got.Month()) != 5 || got.Day() != 12 {
		t.Fatalf("ParseDOB parsed wrong date: %v", got)
	}

	// Whitespace should be trimmed.
	got2 := ParseDOB("  1990-05-12  ")
	if !got2.Equal(got) {
		t.Fatalf("ParseDOB with whitespace = %v, want %v", got2, got)
	}

	// Bad input returns the zero time.
	bad := ParseDOB("not-a-date")
	if !bad.IsZero() {
		t.Fatalf("ParseDOB(bad input) = %v, want zero time", bad)
	}
}
