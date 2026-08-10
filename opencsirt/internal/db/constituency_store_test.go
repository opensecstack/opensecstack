package db

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestConstituencyStoreInsert_DefaultsAppliedBeforeExecFails(t *testing.T) {
	s := NewConstituencyStore(unreachablePool(t))
	c := &Constituency{Name: "Test Org", Sector: "energy"}

	err := s.Insert(context.Background(), c)
	if err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
	if c.ID == uuid.Nil {
		t.Error("Insert did not assign a default ID before failing")
	}
	if c.CreatedAt.IsZero() || c.UpdatedAt.IsZero() {
		t.Error("Insert did not stamp CreatedAt/UpdatedAt before failing")
	}
}

func TestConstituencyStoreInsert_PreservesCallerSuppliedID(t *testing.T) {
	s := NewConstituencyStore(unreachablePool(t))
	id := uuid.New()
	c := &Constituency{ID: id, Name: "Test Org", Sector: "energy"}
	_ = s.Insert(context.Background(), c)

	if c.ID != id {
		t.Errorf("Insert overwrote caller-supplied ID: got %s want %s", c.ID, id)
	}
}

func TestConstituencyStoreGet_PropagatesConnectionError(t *testing.T) {
	s := NewConstituencyStore(unreachablePool(t))
	// A connection-refused error must propagate as-is, not be mapped to
	// ErrNotFound — only pgx.ErrNoRows maps to ErrNotFound.
	_, err := s.Get(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
	if err == ErrNotFound {
		t.Error("a connection error must not be mapped to ErrNotFound")
	}
}

func TestConstituencyStoreUpdate_PropagatesError(t *testing.T) {
	s := NewConstituencyStore(unreachablePool(t))
	c := &Constituency{ID: uuid.New(), Name: "Test Org", Sector: "energy"}
	if err := s.Update(context.Background(), c); err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
}

func TestConstituencyStoreList_PropagatesError(t *testing.T) {
	s := NewConstituencyStore(unreachablePool(t))
	items, total, err := s.List(context.Background(), 10, 0)
	if err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
	if items != nil || total != 0 {
		t.Errorf("List = (%v, %d) alongside an error, want (nil, 0)", items, total)
	}
}

func TestConstituencyStoreList_ClampsLimitAndOffset(t *testing.T) {
	// This only verifies the store does not panic/misbehave on
	// out-of-range paging inputs before hitting the (failing) query --
	// the clamping itself happens purely in-function before any I/O.
	s := NewConstituencyStore(unreachablePool(t))
	cases := []struct {
		limit, offset int
	}{
		{0, 0}, {-1, -1}, {10000, 0}, {5, 5},
	}
	for _, c := range cases {
		if _, _, err := s.List(context.Background(), c.limit, c.offset); err == nil {
			t.Errorf("List(%d,%d): expected an error from an unreachable DB, got nil", c.limit, c.offset)
		}
	}
}
