package db

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/opensecstack/vertguard/internal/audit"
)

func newAuditEvent(action string) *audit.Event {
	return &audit.Event{
		Timestamp:  time.Now().UTC().Truncate(time.Millisecond),
		Actor:      "alice",
		Role:       "admin",
		Action:     action,
		TargetType: "prompt_scan",
		TargetID:   "scan-123",
		Outcome:    "success",
		StatusCode: 200,
		RequestID:  "req-1",
		RemoteIP:   "203.0.113.7",
		Metadata:   json.RawMessage(`{"k":"v"}`),
	}
}

func TestAuditEvent_SaveAndListIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "audit_events")
	ctx := context.Background()

	e := newAuditEvent("scan.create")
	if err := d.SaveAuditEvent(ctx, e); err != nil {
		t.Fatalf("SaveAuditEvent: %v", err)
	}
	if e.ID == uuid.Nil {
		t.Fatal("expected SaveAuditEvent to populate a non-nil ID")
	}

	got, err := d.ListAuditEvents(ctx, 10, "")
	if err != nil {
		t.Fatalf("ListAuditEvents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 event, got %d", len(got))
	}
	if got[0].Actor != "alice" {
		t.Errorf("Actor: got %q, want alice", got[0].Actor)
	}
	if got[0].Action != "scan.create" {
		t.Errorf("Action: got %q, want scan.create", got[0].Action)
	}
	if got[0].RemoteIP != "203.0.113.7" {
		t.Errorf("RemoteIP: got %q, want 203.0.113.7", got[0].RemoteIP)
	}
	var meta map[string]string
	if err := json.Unmarshal(got[0].Metadata, &meta); err != nil {
		t.Fatalf("Metadata did not round-trip as valid JSON: %v (raw: %s)", err, got[0].Metadata)
	}
	if meta["k"] != "v" {
		t.Errorf("Metadata: got %v, want {k: v}", meta)
	}
}

func TestAuditEvent_SavePreservesCallerSuppliedIDIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "audit_events")
	ctx := context.Background()

	e := newAuditEvent("scan.replay")
	e.ID = uuid.New()
	want := e.ID

	if err := d.SaveAuditEvent(ctx, e); err != nil {
		t.Fatalf("SaveAuditEvent: %v", err)
	}
	if e.ID != want {
		t.Errorf("SaveAuditEvent overwrote caller-supplied ID: got %s, want %s", e.ID, want)
	}
}

func TestAuditEvent_SaveNilMetadataAndEmptyFieldsIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "audit_events")
	ctx := context.Background()

	e := &audit.Event{
		Timestamp: time.Now().UTC(),
		Action:    "scan.anonymous",
		Outcome:   "success",
	}
	if err := d.SaveAuditEvent(ctx, e); err != nil {
		t.Fatalf("SaveAuditEvent with empty optional fields: %v", err)
	}

	got, err := d.ListAuditEvents(ctx, 10, "")
	if err != nil {
		t.Fatalf("ListAuditEvents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 event, got %d", len(got))
	}
	if got[0].Actor != "" || got[0].RemoteIP != "" || got[0].TargetType != "" {
		t.Errorf("expected empty optional fields to round-trip empty, got %+v", got[0])
	}
	if got[0].Metadata != nil {
		t.Errorf("expected nil metadata to round-trip nil, got %s", got[0].Metadata)
	}
}

func TestAuditEvent_ListPaginationCursorIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "audit_events")
	ctx := context.Background()

	// Insert three events with strictly increasing timestamps so cursor
	// pagination on (ts, id) is deterministic.
	base := time.Now().UTC().Truncate(time.Millisecond)
	ids := make([]uuid.UUID, 3)
	for i := 0; i < 3; i++ {
		e := newAuditEvent("scan.create")
		e.Timestamp = base.Add(time.Duration(i) * time.Second)
		if err := d.SaveAuditEvent(ctx, e); err != nil {
			t.Fatalf("SaveAuditEvent[%d]: %v", i, err)
		}
		ids[i] = e.ID
	}

	// Full list, newest first.
	all, err := d.ListAuditEvents(ctx, 10, "")
	if err != nil {
		t.Fatalf("ListAuditEvents: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 events, got %d", len(all))
	}
	if all[0].ID != ids[2] {
		t.Errorf("expected newest event first, got %s want %s", all[0].ID, ids[2])
	}

	// Cursor from the newest event should return the older two.
	page, err := d.ListAuditEvents(ctx, 10, ids[2].String())
	if err != nil {
		t.Fatalf("ListAuditEvents with cursor: %v", err)
	}
	if len(page) != 2 {
		t.Fatalf("expected 2 events after cursor, got %d", len(page))
	}
	if page[0].ID != ids[1] || page[1].ID != ids[0] {
		t.Errorf("unexpected page order: %v", page)
	}
}

func TestAuditEvent_ListDefaultAndClampedLimitIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "audit_events")
	ctx := context.Background()

	e := newAuditEvent("scan.create")
	if err := d.SaveAuditEvent(ctx, e); err != nil {
		t.Fatalf("SaveAuditEvent: %v", err)
	}

	// limit <= 0 and limit > 1000 both fall back to the default of 100,
	// they must not error.
	if _, err := d.ListAuditEvents(ctx, 0, ""); err != nil {
		t.Errorf("ListAuditEvents(limit=0): %v", err)
	}
	if _, err := d.ListAuditEvents(ctx, 5000, ""); err != nil {
		t.Errorf("ListAuditEvents(limit=5000): %v", err)
	}
}

func TestAuditEvent_ListEmptyIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "audit_events")

	got, err := d.ListAuditEvents(context.Background(), 10, "")
	if err != nil {
		t.Fatalf("ListAuditEvents: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty list, got %d", len(got))
	}
}
