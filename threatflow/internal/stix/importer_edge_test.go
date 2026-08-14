package stix

import (
	"testing"

	"github.com/rs/zerolog"
)

// TestNewImporter_WiresFieldsWithoutTouchingStore proves the constructor is
// pure (no DB calls) and stores its dependencies as given. Import and
// tagTechniques require a live *store.StixStore/*store.IOCStore/*store.TTPStore
// (concrete pgxpool-backed structs with no fake/interface seam) plus a
// *correlate.Engine, so they are intentionally left untested here.
func TestNewImporter_WiresFieldsWithoutTouchingStore(t *testing.T) {
	imp := NewImporter(nil, nil, nil, nil, zerolog.Nop())
	if imp == nil {
		t.Fatal("NewImporter returned nil")
	}
	if imp.stix != nil || imp.iocs != nil || imp.ttps != nil || imp.correlator != nil {
		t.Error("all dependencies should be nil when nil was passed in")
	}
}

// TestIndicatorToIOC_EmptyPatternReturnsNil covers the "outer" nil-return
// branch in indicatorToIOC: an empty pattern fails ParsePattern with a plain
// (non-ErrUnsupportedPattern-wrapped) error, taking the second `return nil`
// rather than the errors.Is(ErrUnsupportedPattern) branch already covered by
// TestIndicatorToIOC_UnsupportedPatternReturnsNil.
func TestIndicatorToIOC_EmptyPatternReturnsNil(t *testing.T) {
	ind := Indicator{
		Object:  Object{ID: "indicator--8888"},
		Pattern: "",
	}
	if got := indicatorToIOC(ind, "manual", nil); got != nil {
		t.Errorf("expected nil for empty pattern, got %+v", got)
	}
}

// TestValidateObject_RejectsMissingType covers validateObject's
// o.Type == "" branch, not exercised by any existing test (all of which use
// a non-empty type with either a bad id or a mismatched prefix).
func TestValidateObject_RejectsMissingType(t *testing.T) {
	bad := `{
      "type": "bundle",
      "id": "bundle--44444444-4444-4444-4444-444444444444",
      "objects": [{"id":"indicator--11111111-1111-1111-1111-111111111111"}]
    }`
	b, err := ParseBundle([]byte(bad))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := DecodeObjects(b); err == nil {
		t.Fatal("expected error for object missing type")
	}
}

// TestDecodeObjects_RejectsNonArrayObjectsField covers the top-level
// json.Unmarshal(b.Objects, &raws) error branch: `objects` present but not
// a JSON array.
func TestDecodeObjects_RejectsNonArrayObjectsField(t *testing.T) {
	bad := `{"type":"bundle","id":"bundle--44444444-4444-4444-4444-444444444444","objects":{"not":"an array"}}`
	b, err := ParseBundle([]byte(bad))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := DecodeObjects(b); err == nil {
		t.Fatal("expected error for non-array objects field")
	}
}

// TestAsIndicator_TypeMismatchInFieldReturnsError covers the
// json.Unmarshal(o.Raw, &ind) error branch: the envelope type says
// "indicator" (so AsIndicator proceeds past the type guard) but a
// type-specific field has the wrong JSON type.
func TestAsIndicator_TypeMismatchInFieldReturnsError(t *testing.T) {
	bundle := `{
      "type": "bundle",
      "id": "bundle--44444444-4444-4444-4444-444444444444",
      "objects": [
        {"type":"indicator","id":"indicator--11111111-1111-1111-1111-111111111111","pattern":12345}
      ]
    }`
	b, err := ParseBundle([]byte(bundle))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	objs, err := DecodeObjects(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, _, err := AsIndicator(objs[0]); err == nil {
		t.Fatal("expected unmarshal error for pattern field with wrong JSON type")
	}
}

// TestAsMalware_TypeMismatchInFieldReturnsError mirrors the AsIndicator
// case for AsMalware's own unmarshal-error branch.
func TestAsMalware_TypeMismatchInFieldReturnsError(t *testing.T) {
	bundle := `{
      "type": "bundle",
      "id": "bundle--44444444-4444-4444-4444-444444444444",
      "objects": [
        {"type":"malware","id":"malware--22222222-2222-2222-2222-222222222222","is_family":"not-a-bool"}
      ]
    }`
	b, err := ParseBundle([]byte(bundle))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	objs, err := DecodeObjects(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, _, err := AsMalware(objs[0]); err == nil {
		t.Fatal("expected unmarshal error for is_family field with wrong JSON type")
	}
}

// TestAsAttackPattern_TypeMismatchInFieldReturnsError mirrors the same
// unmarshal-error branch for AsAttackPattern.
func TestAsAttackPattern_TypeMismatchInFieldReturnsError(t *testing.T) {
	bundle := `{
      "type": "bundle",
      "id": "bundle--44444444-4444-4444-4444-444444444444",
      "objects": [
        {"type":"attack-pattern","id":"attack-pattern--33333333-3333-3333-3333-333333333333","name":123}
      ]
    }`
	b, err := ParseBundle([]byte(bundle))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	objs, err := DecodeObjects(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, _, err := AsAttackPattern(objs[0]); err == nil {
		t.Fatal("expected unmarshal error for name field with wrong JSON type")
	}
}

// TestAsRelationship_TypeMismatchInFieldReturnsError mirrors the same
// unmarshal-error branch for AsRelationship.
func TestAsRelationship_TypeMismatchInFieldReturnsError(t *testing.T) {
	bundle := `{
      "type": "bundle",
      "id": "bundle--44444444-4444-4444-4444-444444444444",
      "objects": [
        {"type":"relationship","id":"relationship--55555555-5555-5555-5555-555555555555","source_ref":123}
      ]
    }`
	b, err := ParseBundle([]byte(bundle))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	objs, err := DecodeObjects(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, _, err := AsRelationship(objs[0]); err == nil {
		t.Fatal("expected unmarshal error for source_ref field with wrong JSON type")
	}
}

// TestAsVulnerability_TypeMismatchInFieldReturnsError mirrors the same
// unmarshal-error branch for AsVulnerability.
func TestAsVulnerability_TypeMismatchInFieldReturnsError(t *testing.T) {
	bundle := `{
      "type": "bundle",
      "id": "bundle--44444444-4444-4444-4444-444444444444",
      "objects": [
        {"type":"vulnerability","id":"vulnerability--66666666-6666-6666-6666-666666666666","name":true}
      ]
    }`
	b, err := ParseBundle([]byte(bundle))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	objs, err := DecodeObjects(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, _, err := AsVulnerability(objs[0]); err == nil {
		t.Fatal("expected unmarshal error for name field with wrong JSON type")
	}
}
