package handlers

// White-box tests for sanitizeGitHubLogin — it has no exported surface
// (only GitHubOAuthCallback, which needs a live DB and GitHub API, calls
// it), so it is tested here directly. This feeds directly into the
// generated username for new accounts, so its edge cases (empty/short
// logins, disallowed characters) are security/data-integrity relevant.

import "testing"

func TestSanitizeGitHubLogin_AlphanumericPassesThrough(t *testing.T) {
	got := sanitizeGitHubLogin("octocat123")
	if got != "octocat123" {
		t.Errorf("expected 'octocat123' unchanged, got %q", got)
	}
}

func TestSanitizeGitHubLogin_HyphensBecomeUnderscores(t *testing.T) {
	got := sanitizeGitHubLogin("my-cool-login")
	if got != "my_cool_login" {
		t.Errorf("expected hyphens replaced with underscores, got %q", got)
	}
}

func TestSanitizeGitHubLogin_DisallowedCharsReplaced(t *testing.T) {
	got := sanitizeGitHubLogin("weird.login!name")
	want := "weird_login_name"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestSanitizeGitHubLogin_TruncatesTo30Chars(t *testing.T) {
	long := "abcdefghijklmnopqrstuvwxyz0123456789" // 37 chars
	got := sanitizeGitHubLogin(long)
	if len(got) != 30 {
		t.Fatalf("expected result truncated to 30 chars, got %d: %q", len(got), got)
	}
	if got != long[:30] {
		t.Errorf("expected truncation to keep the first 30 chars, got %q", got)
	}
}

func TestSanitizeGitHubLogin_ShortLoginPaddedTo3Chars(t *testing.T) {
	got := sanitizeGitHubLogin("ab")
	if len(got) != 3 {
		t.Fatalf("expected result padded to 3 chars, got %d: %q", len(got), got)
	}
	if got != "ab_" {
		t.Errorf("expected 'ab_', got %q", got)
	}
}

func TestSanitizeGitHubLogin_EmptyLoginBecomesUnderscores(t *testing.T) {
	got := sanitizeGitHubLogin("")
	if got != "___" {
		t.Errorf("expected empty login to become '___', got %q", got)
	}
}

func TestSanitizeGitHubLogin_SingleCharPadded(t *testing.T) {
	got := sanitizeGitHubLogin("x")
	if got != "x__" {
		t.Errorf("expected 'x__', got %q", got)
	}
}
