package csaf

import (
	"errors"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// TestNewImporter_WiresFieldsWithoutTouchingStore proves the constructor is
// pure (no DB calls) and stores its dependencies as given. Ingest itself
// requires a live *store.AdvisoryStore/*store.StixStore (concrete
// pgxpool-backed structs with no fake/interface seam), so it is intentionally
// left untested here — see internal/csaf's DB-dependent Ingest.
func TestNewImporter_WiresFieldsWithoutTouchingStore(t *testing.T) {
	imp := NewImporter(nil, nil, zerolog.Nop())
	if imp == nil {
		t.Fatal("NewImporter returned nil")
	}
	if imp.advisories != nil {
		t.Error("advisories should be nil when nil was passed in")
	}
	if imp.stix != nil {
		t.Error("stix should be nil when nil was passed in")
	}
}

// TestParseDocument_RejectsValidJSONWrongShape covers the branch where
// json.Valid succeeds (the payload is well-formed JSON) but json.Unmarshal
// still fails because the top-level shape isn't an object with the expected
// fields (e.g. a bare JSON string or array).
func TestParseDocument_RejectsValidJSONWrongShape(t *testing.T) {
	cases := []string{`"just a string"`, `42`, `[1,2,3]`}
	for _, c := range cases {
		_, err := ParseDocument([]byte(c))
		if !errors.Is(err, ErrInvalidCSAF) {
			t.Errorf("ParseDocument(%q): want ErrInvalidCSAF, got %v", c, err)
		}
	}
}

// TestValidateDocument_RejectsMissingCategory covers the
// document.category-required branch.
func TestValidateDocument_RejectsMissingCategory(t *testing.T) {
	doc := `{
  "document": {
    "title": "T",
    "publisher": {"category": "coordinator", "name": "OpenCSIRT", "namespace": "https://csirt.example/"},
    "tracking": {"id": "X-1", "initial_release_date": "2026-01-01T00:00:00Z", "current_release_date": "2026-01-01T00:00:00Z"},
    "distribution": {"tlp": {"label": "AMBER"}}
  }
}`
	_, err := ParseDocument([]byte(doc))
	if !errors.Is(err, ErrInvalidCSAF) {
		t.Fatalf("want ErrInvalidCSAF, got %v", err)
	}
}

// TestValidateDocument_RejectsMissingPublisherCategory covers the
// document.publisher.category-required branch.
func TestValidateDocument_RejectsMissingPublisherCategory(t *testing.T) {
	doc := `{
  "document": {
    "category": "csaf_security_advisory",
    "title": "T",
    "publisher": {"name": "OpenCSIRT", "namespace": "https://csirt.example/"},
    "tracking": {"id": "X-1", "initial_release_date": "2026-01-01T00:00:00Z", "current_release_date": "2026-01-01T00:00:00Z"},
    "distribution": {"tlp": {"label": "AMBER"}}
  }
}`
	_, err := ParseDocument([]byte(doc))
	if !errors.Is(err, ErrInvalidCSAF) {
		t.Fatalf("want ErrInvalidCSAF, got %v", err)
	}
}

// TestValidateDocument_RejectsInvalidInitialReleaseDate covers the
// time.Parse error branch for initial_release_date.
func TestValidateDocument_RejectsInvalidInitialReleaseDate(t *testing.T) {
	doc := `{
  "document": {
    "category": "csaf_security_advisory",
    "title": "T",
    "publisher": {"category": "coordinator", "name": "OpenCSIRT", "namespace": "https://csirt.example/"},
    "tracking": {"id": "X-1", "initial_release_date": "not-a-date", "current_release_date": "2026-01-01T00:00:00Z"},
    "distribution": {"tlp": {"label": "AMBER"}}
  }
}`
	_, err := ParseDocument([]byte(doc))
	if !errors.Is(err, ErrInvalidCSAF) {
		t.Fatalf("want ErrInvalidCSAF, got %v", err)
	}
}

// TestValidateDocument_RejectsMissingCurrentReleaseDate covers the
// document.tracking.current_release_date-required branch.
func TestValidateDocument_RejectsMissingCurrentReleaseDate(t *testing.T) {
	doc := `{
  "document": {
    "category": "csaf_security_advisory",
    "title": "T",
    "publisher": {"category": "coordinator", "name": "OpenCSIRT", "namespace": "https://csirt.example/"},
    "tracking": {"id": "X-1", "initial_release_date": "2026-01-01T00:00:00Z", "current_release_date": ""},
    "distribution": {"tlp": {"label": "AMBER"}}
  }
}`
	_, err := ParseDocument([]byte(doc))
	if !errors.Is(err, ErrInvalidCSAF) {
		t.Fatalf("want ErrInvalidCSAF, got %v", err)
	}
}

// TestValidateDocument_RejectsInvalidCurrentReleaseDate covers the
// time.Parse error branch for current_release_date.
func TestValidateDocument_RejectsInvalidCurrentReleaseDate(t *testing.T) {
	doc := `{
  "document": {
    "category": "csaf_security_advisory",
    "title": "T",
    "publisher": {"category": "coordinator", "name": "OpenCSIRT", "namespace": "https://csirt.example/"},
    "tracking": {"id": "X-1", "initial_release_date": "2026-01-01T00:00:00Z", "current_release_date": "also-not-a-date"},
    "distribution": {"tlp": {"label": "AMBER"}}
  }
}`
	_, err := ParseDocument([]byte(doc))
	if !errors.Is(err, ErrInvalidCSAF) {
		t.Fatalf("want ErrInvalidCSAF, got %v", err)
	}
}

// TestMap_DefaultsCSAFVersionWhenEmpty covers orDefault's v=="" branch: the
// existing fixture (validCSAF) always sets csaf_version, so only the
// pass-through branch was exercised before this test.
func TestMap_DefaultsCSAFVersionWhenEmpty(t *testing.T) {
	doc, err := ParseDocument([]byte(validCSAF))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	doc.Document.CSAFVersion = ""
	mapped, err := Map(doc, "opencsirt")
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if mapped.Advisory.CSAFVersion != "2.0" {
		t.Errorf("CSAFVersion = %q, want default 2.0", mapped.Advisory.CSAFVersion)
	}
}

// TestMap_DefaultsStatusWhenEmpty covers Map's inline status=="" -> "final"
// default branch.
func TestMap_DefaultsStatusWhenEmpty(t *testing.T) {
	doc, err := ParseDocument([]byte(validCSAF))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	doc.Document.Tracking.Status = ""
	mapped, err := Map(doc, "opencsirt")
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if mapped.Advisory.Status != "final" {
		t.Errorf("Status = %q, want default final", mapped.Advisory.Status)
	}
}

// TestMap_DefaultsLangWhenEmpty covers Map's inline lang=="" -> "en" default
// branch explicitly (the shared fixture already omits lang, but pinning it
// directly documents the contract).
func TestMap_DefaultsLangWhenEmpty(t *testing.T) {
	doc, err := ParseDocument([]byte(validCSAF))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	doc.Document.Lang = ""
	mapped, err := Map(doc, "opencsirt")
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if mapped.Advisory.Lang != "en" {
		t.Errorf("Lang = %q, want default en", mapped.Advisory.Lang)
	}
}

// TestMap_MissingReleaseDatesReturnsError exercises Map's own error wrap
// around releaseTimes() by handing it a Document whose dates were never
// validated by ParseDocument (constructed directly, bypassing validation —
// exactly the "should indicate a validation bug, not bad input" scenario
// releaseTimes' doc comment describes).
func TestMap_MissingReleaseDatesReturnsError(t *testing.T) {
	doc, err := ParseDocument([]byte(validCSAF))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	doc.Document.Tracking.InitialReleaseDate = "not-a-date-anymore"
	if _, err := Map(doc, "opencsirt"); err == nil {
		t.Fatal("expected Map to surface the releaseTimes parse error")
	}
}

// TestDocument_ReleaseTimes_ErrorOnUnparseableInitialDate calls the
// unexported releaseTimes directly (bypassing ParseDocument's validation) to
// cover the initial-date error-return branch in isolation.
func TestDocument_ReleaseTimes_ErrorOnUnparseableInitialDate(t *testing.T) {
	d := &Document{}
	d.Document.Tracking.InitialReleaseDate = "nope"
	d.Document.Tracking.CurrentReleaseDate = "2026-01-01T00:00:00Z"
	if _, _, err := d.releaseTimes(); err == nil {
		t.Fatal("expected error for unparseable initial_release_date")
	}
}

// TestDocument_ReleaseTimes_ErrorOnUnparseableCurrentDate covers the
// current-date error-return branch (reached only when the initial date
// parses successfully).
func TestDocument_ReleaseTimes_ErrorOnUnparseableCurrentDate(t *testing.T) {
	d := &Document{}
	d.Document.Tracking.InitialReleaseDate = "2026-01-01T00:00:00Z"
	d.Document.Tracking.CurrentReleaseDate = "nope"
	if _, _, err := d.releaseTimes(); err == nil {
		t.Fatal("expected error for unparseable current_release_date")
	}
}

// TestDocument_ReleaseTimes_Success is a sanity check that both dates decode
// to the expected time.Time values when well-formed.
func TestDocument_ReleaseTimes_Success(t *testing.T) {
	d := &Document{}
	d.Document.Tracking.InitialReleaseDate = "2026-01-01T00:00:00Z"
	d.Document.Tracking.CurrentReleaseDate = "2026-02-02T00:00:00Z"
	initial, current, err := d.releaseTimes()
	if err != nil {
		t.Fatalf("releaseTimes: %v", err)
	}
	want := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if !initial.Equal(want) {
		t.Errorf("initial = %v, want %v", initial, want)
	}
	wantCurrent := time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC)
	if !current.Equal(wantCurrent) {
		t.Errorf("current = %v, want %v", current, wantCurrent)
	}
}

// TestOrEmptySlice_NilInputReturnsEmptyNotNil covers orEmptySlice's nil
// branch directly (Map's remediation product_ids field already exercises
// the non-nil branch via the shared fixture).
func TestOrEmptySlice_NilInputReturnsEmptyNotNil(t *testing.T) {
	got := orEmptySlice(nil)
	if got == nil {
		t.Fatal("orEmptySlice(nil) = nil, want non-nil empty slice")
	}
	if len(got) != 0 {
		t.Errorf("orEmptySlice(nil) = %v, want empty", got)
	}
}

// TestOrEmptySlice_NonNilInputPassesThrough covers the pass-through branch
// explicitly.
func TestOrEmptySlice_NonNilInputPassesThrough(t *testing.T) {
	in := []string{"a", "b"}
	got := orEmptySlice(in)
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("orEmptySlice(%v) = %v, want unchanged", in, got)
	}
}

// TestRawMessage_NilInputReturnsJSONNull covers rawMessage's v==nil branch.
func TestRawMessage_NilInputReturnsJSONNull(t *testing.T) {
	got := rawMessage(nil)
	if string(got) != "null" {
		t.Errorf("rawMessage(nil) = %q, want null", got)
	}
}

// TestRawMessage_UnmarshalableInputReturnsJSONNull covers rawMessage's
// json.Marshal-error branch: channels cannot be marshaled to JSON.
func TestRawMessage_UnmarshalableInputReturnsJSONNull(t *testing.T) {
	got := rawMessage(make(chan int))
	if string(got) != "null" {
		t.Errorf("rawMessage(unmarshalable) = %q, want null fallback", got)
	}
}

// TestRawMessage_ValidInputMarshals covers the success branch explicitly.
func TestRawMessage_ValidInputMarshals(t *testing.T) {
	got := rawMessage(map[string]string{"a": "b"})
	if string(got) != `{"a":"b"}` {
		t.Errorf("rawMessage(map) = %s, want {\"a\":\"b\"}", got)
	}
}
