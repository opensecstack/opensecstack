package handlers

// White-box tests for parsePubDate and truncate — pure helpers used by the
// RSS feed handlers (GetFeedRSS, GetUserFeedRSS, GetTagFeedRSS), which
// otherwise require a live DB to exercise.

import (
	"strings"
	"testing"
	"time"
)

func TestParsePubDate_ValidTimestamp_FormatsAsRFC1123Z(t *testing.T) {
	got := parsePubDate("2026-03-14T09:26:53.589793Z")
	want, err := time.Parse("2006-01-02T15:04:05.999999Z07:00", "2026-03-14T09:26:53.589793Z")
	if err != nil {
		t.Fatalf("test setup: %v", err)
	}
	if got != want.Format(time.RFC1123Z) {
		t.Errorf("expected %q, got %q", want.Format(time.RFC1123Z), got)
	}
}

func TestParsePubDate_InvalidTimestamp_FallsBackToNowWithoutError(t *testing.T) {
	before := time.Now()
	got := parsePubDate("not-a-timestamp")
	after := time.Now()

	parsed, err := time.Parse(time.RFC1123Z, got)
	if err != nil {
		t.Fatalf("expected fallback value to still be a valid RFC1123Z timestamp, got %q: %v", got, err)
	}
	if parsed.Before(before.Add(-time.Minute)) || parsed.After(after.Add(time.Minute)) {
		t.Errorf("expected fallback timestamp close to now, got %v (test window %v..%v)", parsed, before, after)
	}
}

func TestParsePubDate_EmptyString_FallsBackToNow(t *testing.T) {
	got := parsePubDate("")
	if _, err := time.Parse(time.RFC1123Z, got); err != nil {
		t.Errorf("expected empty input to fall back to a valid timestamp, got %q: %v", got, err)
	}
}

func TestTruncate_ShorterThanLimit_ReturnsUnchanged(t *testing.T) {
	got := truncate("short", 500)
	if got != "short" {
		t.Errorf("expected unchanged string, got %q", got)
	}
}

func TestTruncate_LongerThanLimit_Truncates(t *testing.T) {
	got := truncate("this is a fairly long sentence", 10)
	if got != "this is a " {
		t.Errorf("expected 'this is a ' (10 chars), got %q", got)
	}
	if len([]rune(got)) != 10 {
		t.Errorf("expected exactly 10 runes, got %d", len([]rune(got)))
	}
}

func TestTruncate_ExactlyAtLimit_ReturnsUnchanged(t *testing.T) {
	s := "1234567890"
	got := truncate(s, 10)
	if got != s {
		t.Errorf("expected unchanged string at exact limit, got %q", got)
	}
}

func TestTruncate_MultiByteRunes_CountedAsRunesNotBytes(t *testing.T) {
	// "café" has 4 runes but 5 bytes (é is 2 bytes in UTF-8). Truncating to 3
	// runes must not split the multi-byte character.
	got := truncate("café", 3)
	if got != "caf" {
		t.Errorf("expected 'caf', got %q", got)
	}
	if !strings.HasPrefix("café", got) {
		t.Errorf("truncated result %q is not a prefix of the original", got)
	}
}
