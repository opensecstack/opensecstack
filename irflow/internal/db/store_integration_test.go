//go:build integration

package db

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/opensecstack/opensecstack/irflow/internal/incident"
)

func TestPGStore_IncidentCRUD(t *testing.T) {
	pool := setupDB(t)
	store := NewPGStore(pool)
	ctx := context.Background()

	inc := &incident.Incident{
		ID:          "inc-test-1",
		Title:       "test incident",
		Description: "integration",
		Severity:    incident.SeverityP2,
		Status:      incident.StatusOpen,
		Source:      incident.SourceManual,
	}
	if err := store.Create(ctx, inc); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := store.Get(ctx, "inc-test-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Title != "test incident" || got.Severity != incident.SeverityP2 {
		t.Errorf("Get mismatch: %+v", got)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Error("timestamps not populated")
	}

	got.Title = "updated"
	got.Status = incident.StatusInvestigating
	if err := store.Update(ctx, got); err != nil {
		t.Fatalf("Update: %v", err)
	}
	after, _ := store.Get(ctx, "inc-test-1")
	if after.Title != "updated" || after.Status != incident.StatusInvestigating {
		t.Errorf("post-update: %+v", after)
	}

	if err := store.Delete(ctx, "inc-test-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get(ctx, "inc-test-1"); err != incident.ErrNotFound {
		t.Errorf("after delete, Get returned %v, want ErrNotFound", err)
	}
}

func TestPGStore_GetMissingReturnsErrNotFound(t *testing.T) {
	pool := setupDB(t)
	store := NewPGStore(pool)
	_, err := store.Get(context.Background(), "inc-does-not-exist")
	if err != incident.ErrNotFound {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestPGStore_ListPaginationAndFilters(t *testing.T) {
	pool := setupDB(t)
	store := NewPGStore(pool)
	ctx := context.Background()

	// Seed with distinct severity/status/source combos. Created_at needs to
	// differ enough that ORDER BY is stable.
	seed := []incident.Incident{
		{ID: "a", Title: "a", Severity: incident.SeverityP1, Status: incident.StatusOpen, Source: incident.SourceAPIGuard},
		{ID: "b", Title: "b", Severity: incident.SeverityP1, Status: incident.StatusContained, Source: incident.SourceCitadel},
		{ID: "c", Title: "c", Severity: incident.SeverityP2, Status: incident.StatusOpen, Source: incident.SourceManual},
		{ID: "d", Title: "d", Severity: incident.SeverityP3, Status: incident.StatusOpen, Source: incident.SourceManual},
	}
	for i := range seed {
		seed[i].CreatedAt = time.Now().Add(time.Duration(i) * time.Second)
		if err := store.Create(ctx, &seed[i]); err != nil {
			t.Fatalf("seed %s: %v", seed[i].ID, err)
		}
	}

	all, total, err := store.List(ctx, incident.ListOptions{Page: 1, PerPage: 10})
	if err != nil {
		t.Fatalf("List all: %v", err)
	}
	if total != 4 || len(all) != 4 {
		t.Errorf("List all: got total=%d len=%d, want 4/4", total, len(all))
	}

	p1, total, err := store.List(ctx, incident.ListOptions{Page: 1, PerPage: 10, Severity: "P1"})
	if err != nil {
		t.Fatalf("List P1: %v", err)
	}
	if total != 2 || len(p1) != 2 {
		t.Errorf("List P1: got total=%d len=%d, want 2/2", total, len(p1))
	}

	manual, total, err := store.List(ctx, incident.ListOptions{Page: 1, PerPage: 1, Source: "manual"})
	if err != nil {
		t.Fatalf("List manual p=1: %v", err)
	}
	if total != 2 || len(manual) != 1 {
		t.Errorf("List manual page=1: got total=%d len=%d, want 2/1", total, len(manual))
	}
}

func TestPGStore_ActionsAndIOCs(t *testing.T) {
	pool := setupDB(t)
	store := NewPGStore(pool)
	ctx := context.Background()

	inc := &incident.Incident{
		ID:       "inc-k",
		Title:    "k",
		Severity: incident.SeverityP2,
		Status:   incident.StatusOpen,
		Source:   incident.SourceManual,
	}
	if err := store.Create(ctx, inc); err != nil {
		t.Fatal(err)
	}

	act := &incident.IncidentAction{
		ID:         "act-1",
		IncidentID: "inc-k",
		ActionType: "contain",
		OperatorID: "alice",
		VerifierID: "bob",
		Evidence:   json.RawMessage(`{"note":"hi"}`),
	}
	if err := store.AddAction(ctx, act); err != nil {
		t.Fatalf("AddAction: %v", err)
	}
	actions, err := store.ListActions(ctx, "inc-k")
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 || actions[0].ActionType != "contain" {
		t.Errorf("ListActions: %+v", actions)
	}

	ioc := &incident.IOCEnrichment{
		IncidentID: "inc-k",
		IOCType:    "ip",
		IOCValue:   "203.0.113.1",
		Confidence: 0.85,
		Source:     "threatflow",
	}
	if err := store.AddIOC(ctx, ioc); err != nil {
		t.Fatalf("AddIOC: %v", err)
	}
	iocs, err := store.ListIOCs(ctx, "inc-k")
	if err != nil {
		t.Fatal(err)
	}
	if len(iocs) != 1 || iocs[0].IOCValue != "203.0.113.1" {
		t.Errorf("ListIOCs: %+v", iocs)
	}
}

func TestPGStore_CascadeDeletes(t *testing.T) {
	pool := setupDB(t)
	store := NewPGStore(pool)
	ctx := context.Background()

	inc := &incident.Incident{ID: "c", Title: "c", Severity: incident.SeverityP3, Status: incident.StatusOpen, Source: incident.SourceManual}
	_ = store.Create(ctx, inc)
	_ = store.AddAction(ctx, &incident.IncidentAction{ID: "a1", IncidentID: "c", ActionType: "x", OperatorID: "o", VerifierID: "v"})
	_ = store.AddIOC(ctx, &incident.IOCEnrichment{IncidentID: "c", IOCType: "ip", IOCValue: "1.2.3.4"})

	if err := store.Delete(ctx, "c"); err != nil {
		t.Fatal(err)
	}
	acts, _ := store.ListActions(ctx, "c")
	iocs, _ := store.ListIOCs(ctx, "c")
	if len(acts) != 0 || len(iocs) != 0 {
		t.Errorf("expected cascade delete, got %d actions / %d iocs", len(acts), len(iocs))
	}
}

func TestPGStore_StatsAggregation(t *testing.T) {
	pool := setupDB(t)
	store := NewPGStore(pool)
	ctx := context.Background()

	fixtures := []incident.Incident{
		{ID: "s1", Title: "t", Severity: incident.SeverityP1, Status: incident.StatusOpen, Source: incident.SourceAPIGuard},
		{ID: "s2", Title: "t", Severity: incident.SeverityP1, Status: incident.StatusContained, Source: incident.SourceAPIGuard},
		{ID: "s3", Title: "t", Severity: incident.SeverityP3, Status: incident.StatusOpen, Source: incident.SourceCitadel},
	}
	for i := range fixtures {
		if err := store.Create(ctx, &fixtures[i]); err != nil {
			t.Fatal(err)
		}
	}

	stats, err := store.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.Total != 3 {
		t.Errorf("Total = %d, want 3", stats.Total)
	}
	if stats.BySeverity["P1"] != 2 || stats.BySeverity["P3"] != 1 {
		t.Errorf("BySeverity = %v", stats.BySeverity)
	}
	if stats.ByStatus["open"] != 2 || stats.ByStatus["contained"] != 1 {
		t.Errorf("ByStatus = %v", stats.ByStatus)
	}
	if stats.BySource["apiguard"] != 2 || stats.BySource["citadel"] != 1 {
		t.Errorf("BySource = %v", stats.BySource)
	}
}
