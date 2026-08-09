package stix

import (
	"errors"
	"strings"
	"testing"
)

// TestParseBundle_RejectsEmptyJSON covers the empty-body failure mode TAXII
// servers occasionally emit on empty collections.
func TestParseBundle_RejectsEmptyJSON(t *testing.T) {
	cases := []string{``, `{}`, `null`, `[]`}
	for _, c := range cases {
		if _, err := ParseBundle([]byte(c)); err == nil {
			t.Errorf("expected error for input %q", c)
		}
	}
}

// TestParseBundle_RejectsMissingObjectsKey guards against feeds that emit the
// bundle envelope but forget the objects array (common MISP-export bug).
func TestParseBundle_RejectsMissingObjectsKey(t *testing.T) {
	payload := `{"type":"bundle","id":"bundle--44444444-4444-4444-4444-444444444444","spec_version":"2.1"}`
	if _, err := ParseBundle([]byte(payload)); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("want ErrInvalidBundle, got %v", err)
	}
}

// TestPattern_EscapedSingleQuotes confirms the parser keeps quoted-literal
// values intact when the indicator value itself contains an apostrophe.
func TestPattern_EscapedSingleQuotes(t *testing.T) {
	// STIX doesn't define a standard escape; most feeds just use double quotes
	// around values that contain apostrophes. Our parser accepts both quote styles.
	typ, val, err := PrimaryIOC(`[domain-name:value = "o'malley.example"]`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if typ != "domain-name" || val != "o'malley.example" {
		t.Errorf("got type=%q value=%q", typ, val)
	}
}

// TestPattern_UnicodeValue verifies non-ASCII indicator values round-trip.
func TestPattern_UnicodeValue(t *testing.T) {
	_, val, err := PrimaryIOC(`[domain-name:value = 'банк.example']`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if val != "банк.example" {
		t.Errorf("unicode value corrupted: %q", val)
	}
}

// TestDecodeObjects_TypeLongerThanID is a regression test for a production
// bug found in validateObject: it computed `o.ID[:len(o.Type)]` to check the
// STIX id-prefix-matches-type convention, without first checking that
// len(o.Type) <= len(o.ID). Since `type` and `id` are independent
// attacker-controlled JSON fields on untrusted feed input (STIX bundles from
// external TAXII servers), a payload with a `type` string longer than its
// `id` string caused a slice-bounds-out-of-range panic — a trivial DoS via
// a single malformed object anywhere in an ingested bundle. Fixed by
// bounds-checking before slicing; this test proves DecodeObjects now returns
// an error instead of crashing the process.
func TestDecodeObjects_TypeLongerThanID(t *testing.T) {
	payload := `{"type":"bundle","id":"bundle--44444444-4444-4444-4444-444444444444","spec_version":"2.1","objects":[` +
		`{"type":"this-type-string-is-deliberately-much-longer-than-the-id-field-below","id":"a--00000000-0000-0000-0000-000000000000"}` +
		`]}`
	b, err := ParseBundle([]byte(payload))
	if err != nil {
		t.Fatalf("parse bundle: %v", err)
	}

	_, err = DecodeObjects(b)
	if err == nil {
		t.Fatal("expected an error for type longer than id, got nil (and no panic — good, but should still be rejected)")
	}
	if !strings.Contains(err.Error(), "object[0]") {
		t.Errorf("error should identify object index, got: %v", err)
	}
}

// TestDecodeObjects_InvalidID surfaces the exact position of a bad id so
// callers can point feed operators at the malformed object.
func TestDecodeObjects_InvalidID(t *testing.T) {
	payload := `{"type":"bundle","id":"bundle--44444444-4444-4444-4444-444444444444","spec_version":"2.1","objects":[{"type":"indicator","id":"indicator--zzzz"}]}`
	b, err := ParseBundle([]byte(payload))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	_, err = DecodeObjects(b)
	if err == nil || !strings.Contains(err.Error(), "object[0]") {
		t.Errorf("error should identify object index, got: %v", err)
	}
}
