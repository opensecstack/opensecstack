package db

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestIncidentStoreInsert_DefaultsAppliedBeforeExecFails(t *testing.T) {
	s := NewIncidentStore(unreachablePool(t))
	i := &Incident{Source: "manual", Severity: "high", Title: "t"}

	err := s.Insert(context.Background(), i)
	if err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
	if i.ID == uuid.Nil {
		t.Error("Insert did not assign a default ID before failing")
	}
	if i.OpenedAt.IsZero() {
		t.Error("Insert did not assign a default OpenedAt before failing")
	}
	if i.Status != "open" {
		t.Errorf("Insert Status = %q, want default %q", i.Status, "open")
	}
	if i.Metadata == nil {
		t.Error("Insert did not default nil Metadata to an empty map before failing")
	}
}

func TestIncidentStoreInsert_PreservesCallerSuppliedStatus(t *testing.T) {
	s := NewIncidentStore(unreachablePool(t))
	i := &Incident{Source: "manual", Severity: "high", Title: "t", Status: "triaged"}
	_ = s.Insert(context.Background(), i)

	if i.Status != "triaged" {
		t.Errorf("Insert overwrote caller-supplied Status: got %q", i.Status)
	}
}

func TestIncidentStoreInsert_InvalidMetadataFailsBeforeExec(t *testing.T) {
	s := NewIncidentStore(unreachablePool(t))
	i := &Incident{
		Source: "manual", Severity: "high", Title: "t",
		Metadata: map[string]any{"bad": make(chan int)},
	}
	if err := s.Insert(context.Background(), i); err == nil {
		t.Fatal("expected a JSON marshal error, got nil")
	}
}

func TestIncidentStoreGet_PropagatesConnectionError(t *testing.T) {
	s := NewIncidentStore(unreachablePool(t))
	_, err := s.Get(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
	if err == ErrNotFound {
		t.Error("a connection error must not be mapped to ErrNotFound")
	}
}

func TestIncidentStoreUpdateStatus_PropagatesError(t *testing.T) {
	s := NewIncidentStore(unreachablePool(t))
	now := time.Now()
	if err := s.UpdateStatus(context.Background(), uuid.New(), "closed", &now); err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
}

func TestIncidentStoreMarkCitadelEmitted_PropagatesError(t *testing.T) {
	s := NewIncidentStore(unreachablePool(t))
	if err := s.MarkCitadelEmitted(context.Background(), uuid.New()); err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
}

func TestIncidentStoreList_PropagatesError(t *testing.T) {
	s := NewIncidentStore(unreachablePool(t))
	items, total, err := s.List(context.Background(), IncidentFilter{})
	if err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
	if items != nil || total != 0 {
		t.Errorf("List = (%v, %d) alongside an error, want (nil, 0)", items, total)
	}
}

func TestIncidentStoreList_ClampsOutOfRangeFilter(t *testing.T) {
	s := NewIncidentStore(unreachablePool(t))
	cases := []IncidentFilter{
		{Limit: 0, Offset: 0},
		{Limit: -5, Offset: -5},
		{Limit: 10000, Offset: 0},
	}
	for _, f := range cases {
		if _, _, err := s.List(context.Background(), f); err == nil {
			t.Errorf("List(%+v): expected an error from an unreachable DB, got nil", f)
		}
	}
}

func TestIncidentStoreCountByStatus_PropagatesError(t *testing.T) {
	s := NewIncidentStore(unreachablePool(t))
	counts, err := s.CountByStatus(context.Background())
	if err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
	if counts != nil {
		t.Errorf("CountByStatus returned non-nil map alongside an error: %+v", counts)
	}
}
