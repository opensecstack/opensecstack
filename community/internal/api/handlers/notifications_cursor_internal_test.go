package handlers

// White-box tests for encodeCursor/decodeCursor — the pagination cursor
// used by ListNotifications. No exported surface exists for these; the
// handler that uses them requires a live DB. Round-trip correctness matters
// because a broken cursor either loops pagination forever or skips rows.

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestCursor_RoundTrip_PreservesTimeAndID(t *testing.T) {
	ts := time.Date(2026, 3, 14, 9, 26, 53, 589793, time.UTC)
	id := "notif-abc-123"

	encoded := encodeCursor(ts, id)
	gotTime, gotID, err := decodeCursor(encoded)
	if err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}
	if !gotTime.Equal(ts) {
		t.Errorf("expected time %v, got %v", ts, gotTime)
	}
	if gotID != id {
		t.Errorf("expected id %q, got %q", id, gotID)
	}
}

func TestCursor_IsURLSafe(t *testing.T) {
	encoded := encodeCursor(time.Now(), "id-with-nothing-special")
	for _, c := range encoded {
		if c == '+' || c == '/' || c == '=' {
			t.Fatalf("expected base64url encoding (no +, /, or =), got %q in %q", c, encoded)
		}
	}
}

func TestDecodeCursor_InvalidBase64_ReturnsError(t *testing.T) {
	_, _, err := decodeCursor("not valid base64url!!!")
	if err == nil {
		t.Fatal("expected error decoding invalid base64")
	}
}

func TestDecodeCursor_MissingUnderscore_ReturnsError(t *testing.T) {
	// Valid base64url, but the decoded payload has no "_" separator.
	bad := encodeCursorRaw(t, "nosplithere")
	_, _, err := decodeCursor(bad)
	if err == nil {
		t.Fatal("expected error decoding a cursor payload with no separator")
	}
}

func TestDecodeCursor_NonNumericTimestamp_ReturnsError(t *testing.T) {
	bad := encodeCursorRaw(t, "notanumber_some-id")
	_, _, err := decodeCursor(bad)
	if err == nil {
		t.Fatal("expected error decoding a cursor with a non-numeric timestamp segment")
	}
}

func TestCursor_IDContainingUnderscore_RoundTrips(t *testing.T) {
	// decodeCursor uses SplitN(..., 2), so an id containing underscores must
	// survive the round trip intact rather than being truncated at the first "_".
	ts := time.Unix(1700000000, 0)
	id := "uuid_with_underscore_segments"

	encoded := encodeCursor(ts, id)
	_, gotID, err := decodeCursor(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotID != id {
		t.Errorf("expected id with embedded underscores to survive round trip, got %q", gotID)
	}
}

// encodeCursorRaw base64url-encodes an arbitrary string (bypassing the
// t/id formatting in encodeCursor) so tests can construct malformed cursor
// payloads.
func encodeCursorRaw(t *testing.T, s string) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}
