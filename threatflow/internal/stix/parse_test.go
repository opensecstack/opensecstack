package stix

import (
	"errors"
	"strings"
	"testing"
)

const minimalBundle = `{
  "type": "bundle",
  "id": "bundle--44444444-4444-4444-4444-444444444444",
  "spec_version": "2.1",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--11111111-1111-1111-1111-111111111111",
      "created": "2026-01-01T00:00:00Z",
      "modified": "2026-01-01T00:00:00Z",
      "pattern_type": "stix",
      "pattern": "[ipv4-addr:value = '1.2.3.4']",
      "valid_from": "2026-01-01T00:00:00Z",
      "indicator_types": ["malicious-activity"],
      "confidence": 80,
      "labels": ["c2"]
    }
  ]
}`

func TestParseBundle_Valid(t *testing.T) {
	b, err := ParseBundle([]byte(minimalBundle))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if b.Type != "bundle" {
		t.Errorf("type = %q", b.Type)
	}
	if !strings.HasPrefix(b.ID, "bundle--") {
		t.Errorf("id = %q", b.ID)
	}
}

func TestParseBundle_RejectsNonBundle(t *testing.T) {
	bad := `{"type":"indicator","id":"indicator--00000000-0000-0000-0000-000000000000","objects":[]}`
	_, err := ParseBundle([]byte(bad))
	if !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("want ErrInvalidBundle, got %v", err)
	}
}

func TestParseBundle_RejectsBadID(t *testing.T) {
	bad := `{"type":"bundle","id":"bundle--nope","objects":[{}]}`
	_, err := ParseBundle([]byte(bad))
	if !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("want ErrInvalidBundle, got %v", err)
	}
}

func TestDecodeObjects_ExtractsIndicator(t *testing.T) {
	b, err := ParseBundle([]byte(minimalBundle))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	objs, err := DecodeObjects(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(objs) != 1 {
		t.Fatalf("want 1 object, got %d", len(objs))
	}
	ind, ok, err := AsIndicator(objs[0])
	if err != nil || !ok {
		t.Fatalf("AsIndicator: ok=%v err=%v", ok, err)
	}
	if ind.Pattern != "[ipv4-addr:value = '1.2.3.4']" {
		t.Errorf("pattern = %q", ind.Pattern)
	}
	if ind.Confidence != 80 {
		t.Errorf("confidence = %d", ind.Confidence)
	}
}

func TestDecodeObjects_RejectsMismatchedIDPrefix(t *testing.T) {
	bad := `{
      "type": "bundle",
      "id": "bundle--44444444-4444-4444-4444-444444444444",
      "objects": [{"type":"indicator","id":"malware--11111111-1111-1111-1111-111111111111"}]
    }`
	b, err := ParseBundle([]byte(bad))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := DecodeObjects(b); err == nil {
		t.Fatal("expected id-prefix error")
	}
}
