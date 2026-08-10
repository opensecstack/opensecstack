package handlers

// White-box tests for deriveGoogleUsername — it has no exported surface
// (only GoogleOAuthCallback, which needs a live DB and Google's token
// endpoint, calls it), so it is tested here directly. This feeds the
// generated username for new Google-SSO accounts.

import "testing"

func TestDeriveGoogleUsername_SimpleEmail_UsesLocalPart(t *testing.T) {
	got := deriveGoogleUsername(&googleIDTokenClaims{Email: "alice@example.com"})
	if got != "alice" {
		t.Errorf("expected 'alice', got %q", got)
	}
}

func TestDeriveGoogleUsername_DotsAndHyphensAndPlusBecomeUnderscore(t *testing.T) {
	got := deriveGoogleUsername(&googleIDTokenClaims{Email: "first.last-name+tag@example.com"})
	want := "first_last_name_tag"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestDeriveGoogleUsername_OtherSpecialCharsStripped(t *testing.T) {
	got := deriveGoogleUsername(&googleIDTokenClaims{Email: "we!rd#user@example.com"})
	want := "werduser"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestDeriveGoogleUsername_TruncatesTo30Chars(t *testing.T) {
	local := "abcdefghijklmnopqrstuvwxyz0123456789" // 37 chars, all valid
	got := deriveGoogleUsername(&googleIDTokenClaims{Email: local + "@example.com"})
	if len(got) != 30 {
		t.Fatalf("expected 30 chars, got %d: %q", len(got), got)
	}
	if got != local[:30] {
		t.Errorf("expected truncation to keep first 30 chars, got %q", got)
	}
}

func TestDeriveGoogleUsername_ShortLocalPartPadded(t *testing.T) {
	got := deriveGoogleUsername(&googleIDTokenClaims{Email: "ab@example.com"})
	if got != "ab_" {
		t.Errorf("expected 'ab_', got %q", got)
	}
}

func TestDeriveGoogleUsername_EmptyLocalPartBecomesUnderscores(t *testing.T) {
	got := deriveGoogleUsername(&googleIDTokenClaims{Email: "@example.com"})
	if got != "___" {
		t.Errorf("expected '___', got %q", got)
	}
}
