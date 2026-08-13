package db

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestAdvisoryStoreLive_InsertGetRoundTrip(t *testing.T) {
	pool := liveDB(t)
	s := NewAdvisoryStore(pool)
	ctx := context.Background()

	a := &Advisory{
		CSAFID:  "CSAF-" + uuid.NewString(),
		Title:   "Live round-trip advisory",
		Summary: "summary",
		CSAFDoc: map[string]any{"document": map[string]any{"title": "t"}},
	}
	if err := s.Insert(ctx, a); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM advisories WHERE id = $1`, a.ID) })

	got, err := s.Get(ctx, a.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.CSAFID != a.CSAFID || got.Title != a.Title || got.State != "draft" || got.TLP != "green" {
		t.Errorf("Get round-trip mismatch: got %+v", got)
	}
	if got.Revision != 1 {
		t.Errorf("Get Revision = %d, want 1", got.Revision)
	}
	doc, ok := got.CSAFDoc["document"].(map[string]any)
	if !ok || doc["title"] != "t" {
		t.Errorf("Get CSAFDoc did not round-trip: %+v", got.CSAFDoc)
	}
}

func TestAdvisoryStoreLive_GetMissingReturnsErrNotFound(t *testing.T) {
	pool := liveDB(t)
	s := NewAdvisoryStore(pool)

	_, err := s.Get(context.Background(), uuid.New())
	if err != ErrNotFound {
		t.Fatalf("Get(missing) error = %v, want ErrNotFound", err)
	}
}

func TestAdvisoryStoreLive_PublishAndWithdrawLifecycle(t *testing.T) {
	pool := liveDB(t)
	s := NewAdvisoryStore(pool)
	ctx := context.Background()

	a := &Advisory{CSAFID: "CSAF-" + uuid.NewString(), Title: "lifecycle"}
	if err := s.Insert(ctx, a); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM advisories WHERE id = $1`, a.ID) })

	by := uuid.New()
	if err := s.Publish(ctx, a.ID, by); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	got, err := s.Get(ctx, a.ID)
	if err != nil {
		t.Fatalf("Get after publish: %v", err)
	}
	if got.State != "published" || got.Revision != 2 || got.PublishedAt == nil || got.PublishedBy == nil {
		t.Errorf("Get after publish = %+v, want published/rev2/stamped", got)
	}

	// Publishing an already-published advisory finds no draft row: ErrNotFound.
	if err := s.Publish(ctx, a.ID, by); err != ErrNotFound {
		t.Errorf("Publish(already published) = %v, want ErrNotFound", err)
	}

	if err := s.Withdraw(ctx, a.ID); err != nil {
		t.Fatalf("Withdraw: %v", err)
	}
	got, err = s.Get(ctx, a.ID)
	if err != nil {
		t.Fatalf("Get after withdraw: %v", err)
	}
	if got.State != "withdrawn" || got.Revision != 3 || got.WithdrawnAt == nil {
		t.Errorf("Get after withdraw = %+v, want withdrawn/rev3/stamped", got)
	}

	// Withdrawing a non-published (already withdrawn) advisory that exists: ErrConflict.
	if err := s.Withdraw(ctx, a.ID); err != ErrConflict {
		t.Errorf("Withdraw(already withdrawn) = %v, want ErrConflict", err)
	}

	// Withdrawing a row that does not exist at all: ErrNotFound.
	if err := s.Withdraw(ctx, uuid.New()); err != ErrNotFound {
		t.Errorf("Withdraw(missing) = %v, want ErrNotFound", err)
	}
}

func TestAdvisoryStoreLive_MarkCitadelEmitted(t *testing.T) {
	pool := liveDB(t)
	s := NewAdvisoryStore(pool)
	ctx := context.Background()

	a := &Advisory{CSAFID: "CSAF-" + uuid.NewString(), Title: "emit"}
	if err := s.Insert(ctx, a); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM advisories WHERE id = $1`, a.ID) })

	if err := s.MarkCitadelEmitted(ctx, a.ID); err != nil {
		t.Fatalf("MarkCitadelEmitted: %v", err)
	}
	got, err := s.Get(ctx, a.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.CitadelEmitted {
		t.Error("MarkCitadelEmitted did not persist citadel_emitted=true")
	}
}

func TestAdvisoryStoreLive_ListAndCountByState(t *testing.T) {
	pool := liveDB(t)
	s := NewAdvisoryStore(pool)
	ctx := context.Background()

	tag := uuid.NewString()
	var ids []uuid.UUID
	for i, state := range []string{"draft", "draft", "published"} {
		a := &Advisory{
			CSAFID: "CSAF-" + tag + "-" + uuid.NewString(),
			Title:  "list-test",
			TLP:    "amber",
		}
		if err := s.Insert(ctx, a); err != nil {
			t.Fatalf("Insert[%d]: %v", i, err)
		}
		ids = append(ids, a.ID)
		if state == "published" {
			if err := s.Publish(ctx, a.ID, uuid.New()); err != nil {
				t.Fatalf("Publish[%d]: %v", i, err)
			}
		}
	}
	t.Cleanup(func() {
		for _, id := range ids {
			_, _ = pool.Exec(context.Background(), `DELETE FROM advisories WHERE id = $1`, id)
		}
	})

	items, total, err := s.List(ctx, AdvisoryFilter{State: "draft", TLP: "amber", Limit: 500})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var draftCount int
	for _, it := range items {
		if it.TLP != "amber" {
			t.Errorf("List returned non-amber item with filter TLP=amber: %+v", it)
		}
		for _, id := range ids {
			if it.ID == id {
				draftCount++
			}
		}
	}
	if draftCount != 2 {
		t.Errorf("List(state=draft) matched %d of our 2 draft rows (total=%d)", draftCount, total)
	}

	// Out-of-range filters are clamped internally rather than erroring.
	if _, _, err := s.List(ctx, AdvisoryFilter{Limit: -5, Offset: -5}); err != nil {
		t.Errorf("List with negative limit/offset: %v", err)
	}
	if _, _, err := s.List(ctx, AdvisoryFilter{Limit: 10000}); err != nil {
		t.Errorf("List with oversized limit: %v", err)
	}

	counts, err := s.CountByState(ctx)
	if err != nil {
		t.Fatalf("CountByState: %v", err)
	}
	if counts["draft"] < 2 || counts["published"] < 1 {
		t.Errorf("CountByState = %+v, want at least draft>=2 published>=1", counts)
	}
}
