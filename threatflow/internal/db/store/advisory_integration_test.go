//go:build integration

package store

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newTestAdvisory(trackingID, revision string) *Advisory {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return &Advisory{
		TrackingID:         trackingID,
		CSAFVersion:        "2.0",
		Revision:           revision,
		Category:           "csaf_security_advisory",
		Title:              "Example advisory " + trackingID,
		Lang:               "en",
		Status:             "final",
		TLPLabel:           "AMBER",
		PublisherName:      "OpenCSIRT",
		PublisherCategory:  "coordinator",
		InitialReleaseDate: now,
		CurrentReleaseDate: now,
		Source:             "opencsirt",
		RawDocument:        []byte(`{"document":{}}`),
	}
}

func TestIntegration_AdvisoryUpsertRevision_CreatesOnFirstSeen(t *testing.T) {
	pool := testDB(t)
	s := NewAdvisoryStore(pool)
	ctx := context.Background()

	res, err := s.UpsertRevision(ctx, &UpsertAdvisoryInput{
		Advisory: newTestAdvisory("OPENCSIRT-TEST-0001", "1"),
		Vulnerabilities: []*AdvisoryVulnerability{
			{CVE: "CVE-2026-00001", Title: "First vuln"},
		},
		DocumentHash: "hash-1",
	})
	mustOK(t, err, "upsert")
	if res.Action != AdvisoryCreated {
		t.Fatalf("action = %q, want created", res.Action)
	}
	if res.Advisory.Revision != "1" {
		t.Errorf("revision = %q, want 1", res.Advisory.Revision)
	}

	detail, err := s.Get(ctx, res.Advisory.ID)
	mustOK(t, err, "get")
	if len(detail.Vulnerabilities) != 1 {
		t.Fatalf("want 1 vulnerability, got %d", len(detail.Vulnerabilities))
	}
}

func TestIntegration_AdvisoryUpsertRevision_NewerVersionUpdatesInPlace(t *testing.T) {
	pool := testDB(t)
	s := NewAdvisoryStore(pool)
	ctx := context.Background()

	first, err := s.UpsertRevision(ctx, &UpsertAdvisoryInput{
		Advisory:        newTestAdvisory("OPENCSIRT-TEST-0002", "1"),
		Vulnerabilities: []*AdvisoryVulnerability{{CVE: "CVE-2026-00002", Title: "v1"}},
		DocumentHash:    "hash-v1",
	})
	mustOK(t, err, "upsert v1")

	rev2 := newTestAdvisory("OPENCSIRT-TEST-0002", "2")
	rev2.Title = "Updated title"
	second, err := s.UpsertRevision(ctx, &UpsertAdvisoryInput{
		Advisory:        rev2,
		Vulnerabilities: []*AdvisoryVulnerability{{CVE: "CVE-2026-00002", Title: "v2 — fixed"}},
		DocumentHash:    "hash-v2",
	})
	mustOK(t, err, "upsert v2")

	if second.Action != AdvisoryUpdated {
		t.Fatalf("action = %q, want updated", second.Action)
	}
	if second.Advisory.ID != first.Advisory.ID {
		t.Fatalf("expected same advisory row (dedup by tracking_id), got %s vs %s", second.Advisory.ID, first.Advisory.ID)
	}
	if second.Advisory.Title != "Updated title" {
		t.Errorf("title = %q, want updated", second.Advisory.Title)
	}

	detail, err := s.Get(ctx, second.Advisory.ID)
	mustOK(t, err, "get")
	if len(detail.Vulnerabilities) != 1 || detail.Vulnerabilities[0].Title != "v2 — fixed" {
		t.Fatalf("vulnerabilities not replaced by new revision: %+v", detail.Vulnerabilities)
	}
}

func TestIntegration_AdvisoryUpsertRevision_SameVersionIsDuplicate(t *testing.T) {
	pool := testDB(t)
	s := NewAdvisoryStore(pool)
	ctx := context.Background()

	first, err := s.UpsertRevision(ctx, &UpsertAdvisoryInput{
		Advisory:        newTestAdvisory("OPENCSIRT-TEST-0003", "1"),
		Vulnerabilities: []*AdvisoryVulnerability{{CVE: "CVE-2026-00003", Title: "v1"}},
		DocumentHash:    "hash-dup",
	})
	mustOK(t, err, "upsert 1")

	dup := newTestAdvisory("OPENCSIRT-TEST-0003", "1")
	dup.Title = "Should be ignored"
	second, err := s.UpsertRevision(ctx, &UpsertAdvisoryInput{
		Advisory:        dup,
		Vulnerabilities: []*AdvisoryVulnerability{{CVE: "CVE-2026-00003", Title: "should not be stored"}},
		DocumentHash:    "hash-dup",
	})
	mustOK(t, err, "upsert 1 again")

	if second.Action != AdvisoryDuplicate {
		t.Fatalf("action = %q, want duplicate", second.Action)
	}
	if second.Advisory.Title != first.Advisory.Title {
		t.Errorf("duplicate resubmission must not change stored title: got %q, want %q",
			second.Advisory.Title, first.Advisory.Title)
	}

	detail, err := s.Get(ctx, first.Advisory.ID)
	mustOK(t, err, "get")
	if len(detail.Vulnerabilities) != 1 || detail.Vulnerabilities[0].Title != "v1" {
		t.Fatalf("duplicate must not touch vulnerabilities, got %+v", detail.Vulnerabilities)
	}
}

func TestIntegration_AdvisoryUpsertRevision_OlderVersionIsStale(t *testing.T) {
	pool := testDB(t)
	s := NewAdvisoryStore(pool)
	ctx := context.Background()

	_, err := s.UpsertRevision(ctx, &UpsertAdvisoryInput{
		Advisory:        newTestAdvisory("OPENCSIRT-TEST-0004", "3"),
		Vulnerabilities: []*AdvisoryVulnerability{{CVE: "CVE-2026-00004", Title: "v3"}},
		DocumentHash:    "hash-v3",
	})
	mustOK(t, err, "upsert v3")

	stale := newTestAdvisory("OPENCSIRT-TEST-0004", "2")
	stale.Title = "Stale attempt"
	res, err := s.UpsertRevision(ctx, &UpsertAdvisoryInput{
		Advisory:        stale,
		Vulnerabilities: []*AdvisoryVulnerability{{CVE: "CVE-2026-00004", Title: "should not apply"}},
		DocumentHash:    "hash-v2-late",
	})
	mustOK(t, err, "upsert stale v2")

	if res.Action != AdvisoryStale {
		t.Fatalf("action = %q, want stale", res.Action)
	}
	if res.Advisory.Revision != "3" {
		t.Errorf("current revision should remain 3, got %q", res.Advisory.Revision)
	}
	if res.Advisory.Title == "Stale attempt" {
		t.Errorf("stale revision must not overwrite current title")
	}
}

func TestIntegration_AdvisoryGetByTrackingID_NotFound(t *testing.T) {
	pool := testDB(t)
	s := NewAdvisoryStore(pool)
	ctx := context.Background()

	_, err := s.GetByTrackingID(ctx, "does-not-exist")
	if err != ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestIntegration_AdvisoryGet_NotFound(t *testing.T) {
	pool := testDB(t)
	s := NewAdvisoryStore(pool)
	ctx := context.Background()

	_, err := s.Get(ctx, uuid.New())
	if err == nil {
		t.Fatal("want error for missing advisory")
	}
}
