package db

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestIncidentStoreLive_InsertGetRoundTrip(t *testing.T) {
	pool := liveDB(t)
	s := NewIncidentStore(pool)
	ctx := context.Background()

	i := &Incident{
		Source:      "manual",
		Severity:    "high",
		Title:       "live round-trip incident",
		Description: "desc",
		Metadata:    map[string]any{"key": "value"},
	}
	if err := s.Insert(ctx, i); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM incidents WHERE id = $1`, i.ID) })

	got, err := s.Get(ctx, i.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Source != i.Source || got.Severity != i.Severity || got.Status != "open" {
		t.Errorf("Get round-trip mismatch: got %+v", got)
	}
	if got.Metadata["key"] != "value" {
		t.Errorf("Get Metadata did not round-trip: %+v", got.Metadata)
	}
}

func TestIncidentStoreLive_GetMissingReturnsErrNotFound(t *testing.T) {
	pool := liveDB(t)
	s := NewIncidentStore(pool)

	_, err := s.Get(context.Background(), uuid.New())
	if err != ErrNotFound {
		t.Fatalf("Get(missing) error = %v, want ErrNotFound", err)
	}
}

func TestIncidentStoreLive_UpdateStatus(t *testing.T) {
	pool := liveDB(t)
	s := NewIncidentStore(pool)
	ctx := context.Background()

	i := &Incident{Source: "manual", Severity: "low", Title: "status"}
	if err := s.Insert(ctx, i); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM incidents WHERE id = $1`, i.ID) })

	closedAt := time.Now().UTC()
	if err := s.UpdateStatus(ctx, i.ID, "closed", &closedAt); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}
	got, err := s.Get(ctx, i.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != "closed" || got.ClosedAt == nil {
		t.Errorf("Get after UpdateStatus = %+v, want status=closed with ClosedAt set", got)
	}

	if err := s.UpdateStatus(ctx, uuid.New(), "closed", nil); err != ErrNotFound {
		t.Errorf("UpdateStatus(missing) = %v, want ErrNotFound", err)
	}
}

func TestIncidentStoreLive_MarkCitadelEmitted(t *testing.T) {
	pool := liveDB(t)
	s := NewIncidentStore(pool)
	ctx := context.Background()

	i := &Incident{Source: "peer_csirt", Severity: "critical", Title: "emit"}
	if err := s.Insert(ctx, i); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM incidents WHERE id = $1`, i.ID) })

	if err := s.MarkCitadelEmitted(ctx, i.ID); err != nil {
		t.Fatalf("MarkCitadelEmitted: %v", err)
	}
	got, err := s.Get(ctx, i.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.CitadelEmitted {
		t.Error("MarkCitadelEmitted did not persist citadel_emitted=true")
	}
}

func TestIncidentStoreLive_ListAndCountByStatus(t *testing.T) {
	pool := liveDB(t)
	s := NewIncidentStore(pool)
	ctx := context.Background()

	tag := uuid.NewString()
	var ids []uuid.UUID
	for _, sev := range []string{"high", "high", "low"} {
		i := &Incident{Source: "manual", Severity: sev, Title: "list-" + tag}
		if err := s.Insert(ctx, i); err != nil {
			t.Fatalf("Insert: %v", err)
		}
		ids = append(ids, i.ID)
	}
	t.Cleanup(func() {
		for _, id := range ids {
			_, _ = pool.Exec(context.Background(), `DELETE FROM incidents WHERE id = $1`, id)
		}
	})

	items, total, err := s.List(ctx, IncidentFilter{Status: "open", Severity: "high", Limit: 500})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var matched int
	for _, it := range items {
		if it.Severity != "high" || it.Status != "open" {
			t.Errorf("List returned item not matching filter: %+v", it)
		}
		for _, id := range ids {
			if it.ID == id {
				matched++
			}
		}
	}
	if matched != 2 {
		t.Errorf("List(severity=high) matched %d of our 2 rows (total=%d)", matched, total)
	}

	if _, _, err := s.List(ctx, IncidentFilter{Limit: -5, Offset: -5}); err != nil {
		t.Errorf("List with negative limit/offset: %v", err)
	}
	if _, _, err := s.List(ctx, IncidentFilter{Limit: 10000}); err != nil {
		t.Errorf("List with oversized limit: %v", err)
	}

	counts, err := s.CountByStatus(ctx)
	if err != nil {
		t.Fatalf("CountByStatus: %v", err)
	}
	if counts["open"] < 3 {
		t.Errorf("CountByStatus = %+v, want open>=3", counts)
	}
}
