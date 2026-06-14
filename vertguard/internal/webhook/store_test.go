package webhook

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// gated by VERTGUARD_TEST_DB_URL — same pattern as the other postgres
// tests in the codebase. Skipped silently when unset so `go test ./...`
// in CI without a DB stays green.
func openTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("VERTGUARD_TEST_DB_URL")
	if url == "" {
		t.Skip("VERTGUARD_TEST_DB_URL not set; skipping postgres test")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return pool
}

func TestStore_UpsertGetDelete(t *testing.T) {
	pool := openTestDB(t)
	defer pool.Close()
	ctx := context.Background()
	s := NewStore(pool)

	sub := &Subscriber{
		URL:         "https://example.test/hook",
		EventTypes:  []string{"prompt_scan"},
		HMACSecrets: []string{"primary", "", ""},
		KeyIDs:      []string{"k1", "", ""},
		Enabled:     true,
		Tenant:      "test",
	}
	if err := s.Upsert(ctx, sub); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if sub.ID == uuid.Nil {
		t.Fatal("ID not assigned")
	}

	got, err := s.Get(ctx, sub.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.URL != sub.URL || got.HMACSecrets[0] != "primary" {
		t.Fatalf("get returned wrong row: %+v", got)
	}

	if err := s.Delete(ctx, sub.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.Get(ctx, sub.ID); err != ErrNotFound {
		t.Fatalf("get after delete: err=%v want ErrNotFound", err)
	}
}

func TestStore_RotateShiftsSlots(t *testing.T) {
	pool := openTestDB(t)
	defer pool.Close()
	ctx := context.Background()
	s := NewStore(pool)

	sub := &Subscriber{
		URL:         "https://example.test/hook",
		HMACSecrets: []string{"p", "n", "old"},
		KeyIDs:      []string{"kp", "kn", "kold"},
		Enabled:     true,
	}
	if err := s.Upsert(ctx, sub); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	defer s.Delete(ctx, sub.ID)

	rotated, err := s.Rotate(ctx, sub.ID, "brand-new", "k-new")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	// After rotate: previous=p, primary=n, next=brand-new.
	if rotated.HMACSecrets[SlotPrevious] != "p" {
		t.Fatalf("previous slot = %q, want 'p'", rotated.HMACSecrets[SlotPrevious])
	}
	if rotated.HMACSecrets[SlotPrimary] != "n" {
		t.Fatalf("primary slot = %q, want 'n'", rotated.HMACSecrets[SlotPrimary])
	}
	if rotated.HMACSecrets[SlotNext] != "brand-new" {
		t.Fatalf("next slot = %q, want 'brand-new'", rotated.HMACSecrets[SlotNext])
	}
}

func TestStore_OutboxLifecycle(t *testing.T) {
	pool := openTestDB(t)
	defer pool.Close()
	ctx := context.Background()
	s := NewStore(pool)

	sub := &Subscriber{
		URL:         "https://example.test/hook",
		HMACSecrets: []string{"p", "", ""},
		KeyIDs:      []string{"k", "", ""},
		Enabled:     true,
	}
	if err := s.Upsert(ctx, sub); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	defer s.Delete(ctx, sub.ID)

	row := &OutboxRow{
		SubscriberID: sub.ID,
		EventID:      "evt-1",
		EventType:    "prompt_scan",
		Payload:      []byte(`{"hello":"world"}`),
	}
	if err := s.EnqueueOutbox(ctx, row); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	pending, err := s.FetchPendingOutbox(ctx, 10)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	found := false
	for _, p := range pending {
		if p.ID == row.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("enqueued row not in pending fetch")
	}
	if err := s.MarkDelivered(ctx, row.ID); err != nil {
		t.Fatalf("mark delivered: %v", err)
	}
}
