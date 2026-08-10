package handlers

// White-box tests for slugify — used to build post URLs from titles, and
// as a tag-name normaliser in buildSearchQuery/buildListByIDsQuery. No
// exported surface exists for it directly.

import "testing"

func TestSlugify_LowercasesAndReplacesSpaces(t *testing.T) {
	got := slugify("My Cool Post Title")
	if got != "my-cool-post-title" {
		t.Errorf("expected 'my-cool-post-title', got %q", got)
	}
}

func TestSlugify_StripsPunctuation(t *testing.T) {
	got := slugify("Hello, World! It's a test.")
	if got != "hello-world-its-a-test" {
		t.Errorf("expected 'hello-world-its-a-test', got %q", got)
	}
}

func TestSlugify_TrimsLeadingAndTrailingHyphens(t *testing.T) {
	got := slugify("  --leading and trailing--  ")
	if got[0] == '-' || got[len(got)-1] == '-' {
		t.Errorf("expected no leading/trailing hyphens, got %q", got)
	}
	if got != "leading-and-trailing" {
		t.Errorf("expected 'leading-and-trailing', got %q", got)
	}
}

func TestSlugify_PreservesDigits(t *testing.T) {
	got := slugify("Top 10 Security Tips 2026")
	if got != "top-10-security-tips-2026" {
		t.Errorf("expected 'top-10-security-tips-2026', got %q", got)
	}
}

func TestSlugify_EmptyString_ReturnsEmpty(t *testing.T) {
	if got := slugify(""); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestSlugify_OnlyPunctuation_ReturnsEmpty(t *testing.T) {
	if got := slugify("!!!???..."); got != "" {
		t.Errorf("expected empty string for punctuation-only input, got %q", got)
	}
}
