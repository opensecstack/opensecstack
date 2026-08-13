package db

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestConstituencyStoreLive_InsertGetUpdate(t *testing.T) {
	pool := liveDB(t)
	s := NewConstituencyStore(pool)
	ctx := context.Background()

	c := &Constituency{
		Name:                "Live Constituency " + uuid.NewString(),
		Sector:              "energy",
		Country:             "AL",
		NIS2Status:          "essential",
		TLPDefault:          "amber",
		PrimaryContactEmail: "csirt@example.test",
	}
	if err := s.Insert(ctx, c); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM constituencies WHERE id = $1`, c.ID) })

	got, err := s.Get(ctx, c.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != c.Name || got.Sector != c.Sector || got.NIS2Status != c.NIS2Status || got.TLPDefault != c.TLPDefault {
		t.Errorf("Get round-trip mismatch: got %+v", got)
	}

	got.Sector = "transport"
	got.NIS2Status = "important"
	if err := s.Update(ctx, got); err != nil {
		t.Fatalf("Update: %v", err)
	}
	updated, err := s.Get(ctx, c.ID)
	if err != nil {
		t.Fatalf("Get after update: %v", err)
	}
	if updated.Sector != "transport" || updated.NIS2Status != "important" {
		t.Errorf("Get after update = %+v, want sector=transport nis2_status=important", updated)
	}
	if !updated.UpdatedAt.After(c.UpdatedAt) && updated.UpdatedAt != c.UpdatedAt {
		t.Errorf("Update did not advance UpdatedAt: before=%v after=%v", c.UpdatedAt, updated.UpdatedAt)
	}
}

func TestConstituencyStoreLive_GetMissingReturnsErrNotFound(t *testing.T) {
	pool := liveDB(t)
	s := NewConstituencyStore(pool)

	_, err := s.Get(context.Background(), uuid.New())
	if err != ErrNotFound {
		t.Fatalf("Get(missing) error = %v, want ErrNotFound", err)
	}
}

func TestConstituencyStoreLive_UpdateMissingReturnsErrNotFound(t *testing.T) {
	pool := liveDB(t)
	s := NewConstituencyStore(pool)

	c := &Constituency{ID: uuid.New(), Name: "ghost", Sector: "x", Country: "AL", NIS2Status: "essential"}
	if err := s.Update(context.Background(), c); err != ErrNotFound {
		t.Fatalf("Update(missing) error = %v, want ErrNotFound", err)
	}
}

func TestConstituencyStoreLive_List(t *testing.T) {
	pool := liveDB(t)
	s := NewConstituencyStore(pool)
	ctx := context.Background()

	tag := uuid.NewString()
	var ids []uuid.UUID
	for i := 0; i < 3; i++ {
		c := &Constituency{
			Name: tag, Sector: "energy", Country: "AL",
			NIS2Status:          "essential",
			TLPDefault:          "green",
			PrimaryContactEmail: "csirt@example.test",
		}
		// Name+Country is UNIQUE, so vary Name per row.
		c.Name = "Live List " + tag + " " + uuid.NewString()
		if err := s.Insert(ctx, c); err != nil {
			t.Fatalf("Insert[%d]: %v", i, err)
		}
		ids = append(ids, c.ID)
	}
	t.Cleanup(func() {
		for _, id := range ids {
			_, _ = pool.Exec(context.Background(), `DELETE FROM constituencies WHERE id = $1`, id)
		}
	})

	items, total, err := s.List(ctx, 500, 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total < 3 {
		t.Errorf("List total = %d, want >= 3", total)
	}
	var found int
	for _, it := range items {
		for _, id := range ids {
			if it.ID == id {
				found++
			}
		}
	}
	if found != 3 {
		t.Errorf("List returned %d of our 3 inserted rows", found)
	}

	// Clamping: negative/zero limit and negative offset must not error.
	if _, _, err := s.List(ctx, 0, -5); err != nil {
		t.Errorf("List(0,-5): %v", err)
	}
	if _, _, err := s.List(ctx, 10000, 0); err != nil {
		t.Errorf("List(10000,0): %v", err)
	}
}
