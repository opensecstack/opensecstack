// Tests for the typed outbox event constructors (events.go).
package citadel

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// fakeEnqueuer records the EnqueueRequest it was called with and
// returns a canned id/err.
type fakeEnqueuer struct {
	lastReq EnqueueRequest
	nextID  int64
	err     error
	calls   int
}

func (f *fakeEnqueuer) Enqueue(_ context.Context, req EnqueueRequest) (int64, error) {
	f.calls++
	f.lastReq = req
	if f.err != nil {
		return 0, f.err
	}
	return f.nextID, nil
}

func TestEnqueueCohortCreated(t *testing.T) {
	fe := &fakeEnqueuer{nextID: 11}
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	id, err := EnqueueCohortCreated(context.Background(), fe, CohortCreated{
		CohortID:      "c-1",
		TenantID:      "t-1",
		Name:          "Cohort One",
		TrackID:       "trk-1",
		CreatedBy:     "u-1",
		CreatedAt:     created,
		CorrelationID: "corr-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != 11 {
		t.Fatalf("expected id=11, got %d", id)
	}
	if fe.lastReq.Destination != "citadel" {
		t.Fatalf("expected destination=citadel, got %q", fe.lastReq.Destination)
	}
	if fe.lastReq.EventType != "cyberpath.cohort.created" {
		t.Fatalf("expected event_type=cyberpath.cohort.created, got %q", fe.lastReq.EventType)
	}
	if fe.lastReq.CorrelationID != "corr-1" {
		t.Fatalf("expected correlation_id=corr-1, got %q", fe.lastReq.CorrelationID)
	}

	var payload map[string]any
	if err := json.Unmarshal(fe.lastReq.Payload, &payload); err != nil {
		t.Fatalf("payload not valid JSON: %v", err)
	}
	if payload["subject"] != "cohort:c-1" {
		t.Fatalf("expected subject=cohort:c-1, got %v", payload["subject"])
	}
	cp := payload["cyberpath"].(map[string]any)
	if cp["cohort_id"] != "c-1" || cp["name"] != "Cohort One" || cp["track_id"] != "trk-1" || cp["created_by"] != "u-1" {
		t.Fatalf("unexpected cyberpath block: %+v", cp)
	}
	if payload["timestamp"] != created.UTC().Format(time.RFC3339) {
		t.Fatalf("expected timestamp %s, got %v", created.UTC().Format(time.RFC3339), payload["timestamp"])
	}
}

// EnqueueCompletionWORM must reject rows missing user_id or
// completion_id (the two fields the WORM audit chain relies on to
// stitch evidence back to a subject) — this is a hard invariant since
// NIS2 evidence with a missing subject is not auditable.
func TestEnqueueCompletionWORM_RequiredFields(t *testing.T) {
	fe := &fakeEnqueuer{nextID: 1}

	if _, err := EnqueueCompletionWORM(context.Background(), fe, CompletionWORM{CompletionID: "c-1"}); err == nil {
		t.Fatalf("expected error when UserID is empty")
	}
	if _, err := EnqueueCompletionWORM(context.Background(), fe, CompletionWORM{UserID: "u-1"}); err == nil {
		t.Fatalf("expected error when CompletionID is empty")
	}
	if fe.calls != 0 {
		t.Fatalf("store must not be called on validation failure, got %d calls", fe.calls)
	}
}

// Categories default to "nis2.<measure>" per NIS2Measures when the
// caller doesn't supply Categories explicitly; Patterns default to
// "track:<id>" similarly. Both must be overridable.
func TestEnqueueCompletionWORM_Defaults(t *testing.T) {
	fe := &fakeEnqueuer{nextID: 5}
	_, err := EnqueueCompletionWORM(context.Background(), fe, CompletionWORM{
		UserID:       "u-1",
		CompletionID: "comp-1",
		TrackID:      "trk-9",
		NIS2Measures: []string{"art21", "art23"},
		Score:        0.95,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var payload map[string]any
	_ = json.Unmarshal(fe.lastReq.Payload, &payload)

	cats, ok := payload["categories"].([]any)
	if !ok || len(cats) != 2 || cats[0] != "nis2.art21" || cats[1] != "nis2.art23" {
		t.Fatalf("expected default categories from NIS2Measures, got %v", payload["categories"])
	}
	pats, ok := payload["patterns"].([]any)
	if !ok || len(pats) != 1 || pats[0] != "track:trk-9" {
		t.Fatalf("expected default pattern track:trk-9, got %v", payload["patterns"])
	}
	if payload["verdict"] != "completed" {
		t.Fatalf("expected verdict=completed, got %v", payload["verdict"])
	}
	if payload["score"] != 0.95 {
		t.Fatalf("expected score=0.95, got %v", payload["score"])
	}

	// Explicit Categories/Patterns override the defaults.
	fe2 := &fakeEnqueuer{nextID: 6}
	_, err = EnqueueCompletionWORM(context.Background(), fe2, CompletionWORM{
		UserID:       "u-2",
		CompletionID: "comp-2",
		NIS2Measures: []string{"art21"},
		Categories:   []string{"custom.cat"},
		Patterns:     []string{"custom.pattern"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var payload2 map[string]any
	_ = json.Unmarshal(fe2.lastReq.Payload, &payload2)
	cats2 := payload2["categories"].([]any)
	if len(cats2) != 1 || cats2[0] != "custom.cat" {
		t.Fatalf("expected explicit categories to be preserved, got %v", cats2)
	}
	pats2 := payload2["patterns"].([]any)
	if len(pats2) != 1 || pats2[0] != "custom.pattern" {
		t.Fatalf("expected explicit patterns to be preserved, got %v", pats2)
	}
}

func TestEnqueueCertificationIssued(t *testing.T) {
	fe := &fakeEnqueuer{nextID: 3}
	expires := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err := EnqueueCertificationIssued(context.Background(), fe, CertificationIssued{
		CertificateID:      "cert-1",
		UserID:             "u-1",
		TrackID:            "trk-1",
		CertificationLevel: "track-cert",
		ExpiresAt:          &expires,
		SignedBy:           "ed25519:abc",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var payload map[string]any
	_ = json.Unmarshal(fe.lastReq.Payload, &payload)
	if payload["event_type"] != "cyberpath.certification.issued" {
		t.Fatalf("unexpected event_type: %v", payload["event_type"])
	}
	cb := payload["cyberpath"].(map[string]any)
	if cb["expires_at"] != expires.UTC().Format(time.RFC3339) {
		t.Fatalf("expected expires_at to be set, got %v", cb["expires_at"])
	}

	// Nil ExpiresAt must NOT add the key at all.
	fe2 := &fakeEnqueuer{nextID: 4}
	_, _ = EnqueueCertificationIssued(context.Background(), fe2, CertificationIssued{
		CertificateID: "cert-2", UserID: "u-2",
	})
	var payload2 map[string]any
	_ = json.Unmarshal(fe2.lastReq.Payload, &payload2)
	cb2 := payload2["cyberpath"].(map[string]any)
	if _, ok := cb2["expires_at"]; ok {
		t.Fatalf("expected no expires_at key when ExpiresAt is nil, got %v", cb2["expires_at"])
	}
}

func TestEnqueueCertificationRevoked_RequiresCertificateID(t *testing.T) {
	fe := &fakeEnqueuer{nextID: 1}
	if _, err := EnqueueCertificationRevoked(context.Background(), fe, CertificationRevoked{}); err == nil {
		t.Fatalf("expected error when CertificateID is empty")
	}
	if fe.calls != 0 {
		t.Fatalf("store must not be called on validation failure")
	}

	_, err := EnqueueCertificationRevoked(context.Background(), fe, CertificationRevoked{
		CertificateID: "cert-9",
		RevokedBy:     "admin-1",
		Reason:        "policy violation",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var payload map[string]any
	_ = json.Unmarshal(fe.lastReq.Payload, &payload)
	if payload["subject"] != "certification:cert-9" {
		t.Fatalf("expected subject=certification:cert-9, got %v", payload["subject"])
	}
	cb := payload["cyberpath"].(map[string]any)
	if cb["reason"] != "policy violation" {
		t.Fatalf("expected reason to be set, got %v", cb["reason"])
	}

	// Empty Reason must NOT add the key.
	fe2 := &fakeEnqueuer{nextID: 2}
	_, _ = EnqueueCertificationRevoked(context.Background(), fe2, CertificationRevoked{CertificateID: "cert-10"})
	var payload2 map[string]any
	_ = json.Unmarshal(fe2.lastReq.Payload, &payload2)
	cb2 := payload2["cyberpath"].(map[string]any)
	if _, ok := cb2["reason"]; ok {
		t.Fatalf("expected no reason key when Reason is empty")
	}
}

func TestEnqueueLabCompleted(t *testing.T) {
	fe := &fakeEnqueuer{nextID: 7}
	_, err := EnqueueLabCompleted(context.Background(), fe, LabCompleted{
		LabSessionID: "sess-1",
		LabID:        "lab-1",
		UserID:       "u-1",
		Outcome:      "pass",
		Score:        1.0,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fe.lastReq.EventType != "cyberpath.lab.completed" {
		t.Fatalf("unexpected event type: %q", fe.lastReq.EventType)
	}
	var payload map[string]any
	_ = json.Unmarshal(fe.lastReq.Payload, &payload)
	cb := payload["cyberpath"].(map[string]any)
	if cb["outcome"] != "pass" {
		t.Fatalf("expected outcome=pass, got %v", cb["outcome"])
	}
}

// enqueueJSON: nil store must error without panicking.
func TestEnqueueJSON_NilStore(t *testing.T) {
	_, err := EnqueueCohortCreated(context.Background(), nil, CohortCreated{CohortID: "c-1"})
	if err == nil {
		t.Fatalf("expected error for nil store")
	}
}

// enqueueJSON must propagate the underlying store's error.
func TestEnqueueJSON_StoreError(t *testing.T) {
	fe := &fakeEnqueuer{err: errors.New("db down")}
	_, err := EnqueueCohortCreated(context.Background(), fe, CohortCreated{CohortID: "c-1"})
	if err == nil {
		t.Fatalf("expected store error to propagate")
	}
}

// tsOrNow: zero time falls back to "now" (within a generous bound);
// non-zero time round-trips as RFC3339 UTC.
func TestTsOrNow(t *testing.T) {
	fixed := time.Date(2025, 6, 15, 10, 30, 0, 0, time.FixedZone("CEST", 2*3600))
	got := tsOrNow(fixed)
	want := fixed.UTC().Format(time.RFC3339)
	if got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}

	before := time.Now().UTC()
	got2 := tsOrNow(time.Time{})
	parsed, err := time.Parse(time.RFC3339, got2)
	if err != nil {
		t.Fatalf("tsOrNow(zero) did not produce RFC3339: %v", err)
	}
	after := time.Now().UTC()
	if parsed.Before(before.Add(-2*time.Second)) || parsed.After(after.Add(2*time.Second)) {
		t.Fatalf("tsOrNow(zero) should be close to now, got %v (window %v..%v)", parsed, before, after)
	}
}
