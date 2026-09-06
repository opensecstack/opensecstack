// These tests need a real, migrated `compliance_evidence`/`worm_entries`
// schema. Following the same convention as worm_anchor_test.go: read
// DATABASE_URL and skip (not fail) when unset, no build tag, so they run as
// part of the plain `go test ./...` CI's test-citadel job already invokes
// (see .github/workflows/ci.yml).

package db

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/google/uuid"
)

// TestInsertComplianceEvidence_RoundTrip confirms a submitted evidence
// record can be inserted and read back byte-for-byte, including its report
// JSONB body and its link to a real WORM entry.
func TestInsertComplianceEvidence_RoundTrip(t *testing.T) {
	d := anchorTestDB(t)
	ctx := context.Background()
	source := uniqueSource(t)

	wormEntry, err := d.AppendWORM(ctx, source, "compliance_evidence_submitted", "nis2compass", []byte(`{"x":1}`), "", "")
	if err != nil {
		t.Fatalf("AppendWORM: %v", err)
	}

	report := []byte(`{"schema_version":"1.0","report_type":"nis2_compliance"}`)
	entry, err := d.InsertComplianceEvidence(ctx, "org-1", "assessment-1", "1.0", "deadbeef", report, "user-abc", wormEntry.ID)
	if err != nil {
		t.Fatalf("InsertComplianceEvidence: %v", err)
	}
	if entry.ID == uuid.Nil {
		t.Fatal("expected a non-nil evidence ID")
	}

	got, exists, err := d.GetComplianceEvidence(ctx, entry.ID)
	if err != nil {
		t.Fatalf("GetComplianceEvidence: %v", err)
	}
	if !exists {
		t.Fatal("expected the just-inserted evidence record to exist")
	}
	if got.OrganisationID != "org-1" || got.AssessmentID != "assessment-1" {
		t.Errorf("got org/assessment = %q/%q, want org-1/assessment-1", got.OrganisationID, got.AssessmentID)
	}
	if got.SchemaVersion != "1.0" {
		t.Errorf("got schema_version = %q, want 1.0", got.SchemaVersion)
	}
	if got.ReportHash != "deadbeef" {
		t.Errorf("got report_hash = %q, want deadbeef", got.ReportHash)
	}
	// Postgres JSONB re-serialises (key order/whitespace may differ from the
	// exact bytes written), so compare decoded values, not raw bytes.
	var gotReport, wantReport map[string]any
	if err := json.Unmarshal(got.Report, &gotReport); err != nil {
		t.Fatalf("unmarshal got.Report: %v", err)
	}
	if err := json.Unmarshal(report, &wantReport); err != nil {
		t.Fatalf("unmarshal want report: %v", err)
	}
	if !reflect.DeepEqual(gotReport, wantReport) {
		t.Errorf("got report = %s, want %s", got.Report, report)
	}
	if got.SubmittedBy != "user-abc" {
		t.Errorf("got submitted_by = %q, want user-abc", got.SubmittedBy)
	}
	if got.WORMEntryID != wormEntry.ID {
		t.Errorf("got worm_entry_id = %v, want %v", got.WORMEntryID, wormEntry.ID)
	}
}

// TestGetComplianceEvidence_NotFoundIsNotAnError confirms a missing id
// reports exists=false with a nil error, not an error — a real query
// failure must be distinguishable from "no such record" by callers.
func TestGetComplianceEvidence_NotFoundIsNotAnError(t *testing.T) {
	d := anchorTestDB(t)
	ctx := context.Background()

	got, exists, err := d.GetComplianceEvidence(ctx, uuid.New())
	if err != nil {
		t.Fatalf("expected no error for a missing id, got: %v", err)
	}
	if exists {
		t.Fatal("expected exists=false for a random id that was never inserted")
	}
	if got != nil {
		t.Errorf("expected nil entry when exists=false, got %+v", got)
	}
}

// TestListComplianceEvidence_FiltersByOrgAndAssessment confirms List only
// returns rows matching the given filters, ordered newest-submitted-first,
// and that an empty filter value means "any" for that column.
func TestListComplianceEvidence_FiltersByOrgAndAssessment(t *testing.T) {
	d := anchorTestDB(t)
	ctx := context.Background()
	source := uniqueSource(t)

	orgA := "org-list-" + source
	orgB := "org-list-other-" + source
	assessment1 := "assessment-list-1-" + source

	mustInsert := func(org, assessment string) uuid.UUID {
		t.Helper()
		wormEntry, err := d.AppendWORM(ctx, source, "compliance_evidence_submitted", "nis2compass", []byte(`{}`), "", "")
		if err != nil {
			t.Fatalf("AppendWORM: %v", err)
		}
		entry, err := d.InsertComplianceEvidence(ctx, org, assessment, "1.0", "hash", []byte(`{}`), "user", wormEntry.ID)
		if err != nil {
			t.Fatalf("InsertComplianceEvidence: %v", err)
		}
		return entry.ID
	}

	wantID := mustInsert(orgA, assessment1)
	mustInsert(orgB, assessment1)                 // different org, same assessment — must be excluded
	mustInsert(orgA, "assessment-list-2-"+source) // same org, different assessment — must be excluded

	results, err := d.ListComplianceEvidence(ctx, orgA, assessment1)
	if err != nil {
		t.Fatalf("ListComplianceEvidence: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected exactly 1 result for org=%s assessment=%s, got %d", orgA, assessment1, len(results))
	}
	if results[0].ID != wantID {
		t.Errorf("got id %v, want %v", results[0].ID, wantID)
	}
}

// TestListComplianceEvidence_NoMatchesReturnsEmptyNotError confirms a
// filter combination with zero matches returns an empty (possibly nil)
// slice and no error, rather than surfacing "no rows" as a failure.
func TestListComplianceEvidence_NoMatchesReturnsEmptyNotError(t *testing.T) {
	d := anchorTestDB(t)
	ctx := context.Background()

	results, err := d.ListComplianceEvidence(ctx, "org-that-does-not-exist-"+uuid.New().String(), "")
	if err != nil {
		t.Fatalf("expected no error for zero matches, got: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}
