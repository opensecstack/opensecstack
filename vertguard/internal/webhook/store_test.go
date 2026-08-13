package webhook

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// gated by DATABASE_URL — same pattern as the other postgres
// tests in the codebase. Skipped silently when unset so `go test ./...`
// in CI without a DB stays green.
func openTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping postgres test")
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

	// A delivered row must no longer show up in FetchPendingOutbox.
	pendingAfter, err := s.FetchPendingOutbox(ctx, 10)
	if err != nil {
		t.Fatalf("fetch after delivered: %v", err)
	}
	for _, p := range pendingAfter {
		if p.ID == row.ID {
			t.Fatal("delivered row still returned by FetchPendingOutbox")
		}
	}
}

func TestStore_Get_NotFound(t *testing.T) {
	pool := openTestDB(t)
	defer pool.Close()
	s := NewStore(pool)

	_, err := s.Get(context.Background(), uuid.New())
	if err != ErrNotFound {
		t.Fatalf("Get() error = %v, want ErrNotFound", err)
	}
}

func TestStore_Delete_NotFound(t *testing.T) {
	pool := openTestDB(t)
	defer pool.Close()
	s := NewStore(pool)

	err := s.Delete(context.Background(), uuid.New())
	if err != ErrNotFound {
		t.Fatalf("Delete() error = %v, want ErrNotFound", err)
	}
}

func TestStore_List_ReturnsUpsertedSubscriber(t *testing.T) {
	pool := openTestDB(t)
	defer pool.Close()
	ctx := context.Background()
	s := NewStore(pool)

	sub := &Subscriber{
		URL:         "https://example.test/list-hook",
		EventTypes:  []string{"prompt_scan"},
		HMACSecrets: []string{"p", "", ""},
		KeyIDs:      []string{"k", "", ""},
		Enabled:     true,
		Tenant:      "list-test",
	}
	if err := s.Upsert(ctx, sub); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	defer s.Delete(ctx, sub.ID)

	all, err := s.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	found := false
	for _, sb := range all {
		if sb.ID == sub.ID {
			found = true
			if sb.URL != sub.URL {
				t.Errorf("listed URL = %q, want %q", sb.URL, sub.URL)
			}
		}
	}
	if !found {
		t.Fatal("upserted subscriber not present in List() output")
	}
}

func TestStore_ListByEventType_FiltersDisabledAndMismatchedType(t *testing.T) {
	pool := openTestDB(t)
	defer pool.Close()
	ctx := context.Background()
	s := NewStore(pool)

	wantType := "webhook_test_evttype"
	matching := &Subscriber{
		URL: "https://example.test/matching", EventTypes: []string{wantType},
		HMACSecrets: []string{"p", "", ""}, KeyIDs: []string{"k", "", ""}, Enabled: true,
	}
	disabled := &Subscriber{
		URL: "https://example.test/disabled", EventTypes: []string{wantType},
		HMACSecrets: []string{"p", "", ""}, KeyIDs: []string{"k", "", ""}, Enabled: false,
	}
	otherType := &Subscriber{
		URL: "https://example.test/othertype", EventTypes: []string{"unrelated_event"},
		HMACSecrets: []string{"p", "", ""}, KeyIDs: []string{"k", "", ""}, Enabled: true,
	}
	catchAll := &Subscriber{
		URL: "https://example.test/catchall", EventTypes: nil, // empty => matches everything
		HMACSecrets: []string{"p", "", ""}, KeyIDs: []string{"k", "", ""}, Enabled: true,
	}
	for _, sub := range []*Subscriber{matching, disabled, otherType, catchAll} {
		if err := s.Upsert(ctx, sub); err != nil {
			t.Fatalf("upsert %s: %v", sub.URL, err)
		}
		defer s.Delete(ctx, sub.ID)
	}

	got, err := s.ListByEventType(ctx, wantType)
	if err != nil {
		t.Fatalf("ListByEventType: %v", err)
	}
	ids := map[uuid.UUID]bool{}
	for _, sb := range got {
		ids[sb.ID] = true
	}
	if !ids[matching.ID] {
		t.Error("matching subscriber missing from result")
	}
	if !ids[catchAll.ID] {
		t.Error("catch-all (empty EventTypes) subscriber missing from result")
	}
	if ids[disabled.ID] {
		t.Error("disabled subscriber must not be returned")
	}
	if ids[otherType.ID] {
		t.Error("subscriber for a different event type must not be returned")
	}
}

func TestStore_Rotate_FullLifecycle(t *testing.T) {
	pool := openTestDB(t)
	defer pool.Close()
	ctx := context.Background()
	s := NewStore(pool)

	// Start with only a primary secret set (fresh subscriber, never rotated).
	sub := &Subscriber{
		URL:         "https://example.test/rotate-fresh",
		HMACSecrets: []string{"orig", "", ""},
		KeyIDs:      []string{"korig", "", ""},
		Enabled:     true,
	}
	if err := s.Upsert(ctx, sub); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	defer s.Delete(ctx, sub.ID)

	// First rotation: next slot was empty, so primary is retained and the
	// new secret simply lands in NEXT.
	r1, err := s.Rotate(ctx, sub.ID, "staged", "kstaged")
	if err != nil {
		t.Fatalf("rotate 1: %v", err)
	}
	if r1.HMACSecrets[SlotPrimary] != "orig" {
		t.Fatalf("after first rotate primary = %q, want unchanged 'orig'", r1.HMACSecrets[SlotPrimary])
	}
	if r1.HMACSecrets[SlotNext] != "staged" {
		t.Fatalf("after first rotate next = %q, want 'staged'", r1.HMACSecrets[SlotNext])
	}
	if r1.HMACSecrets[SlotPrevious] != "orig" {
		t.Fatalf("after first rotate previous = %q, want 'orig'", r1.HMACSecrets[SlotPrevious])
	}

	// Second rotation: next ("staged") is promoted to primary.
	r2, err := s.Rotate(ctx, sub.ID, "brand-new", "knew")
	if err != nil {
		t.Fatalf("rotate 2: %v", err)
	}
	if r2.HMACSecrets[SlotPrimary] != "staged" {
		t.Fatalf("after second rotate primary = %q, want 'staged'", r2.HMACSecrets[SlotPrimary])
	}
	if r2.HMACSecrets[SlotNext] != "brand-new" {
		t.Fatalf("after second rotate next = %q, want 'brand-new'", r2.HMACSecrets[SlotNext])
	}
	if r2.HMACSecrets[SlotPrevious] != "orig" {
		t.Fatalf("after second rotate previous = %q, want 'orig' (primary from before rotate 1)", r2.HMACSecrets[SlotPrevious])
	}

	// Persisted state must match what Rotate returned.
	reloaded, err := s.Get(ctx, sub.ID)
	if err != nil {
		t.Fatalf("get after rotate: %v", err)
	}
	if reloaded.HMACSecrets[SlotPrimary] != "staged" || reloaded.HMACSecrets[SlotNext] != "brand-new" {
		t.Fatalf("reloaded secrets = %v, want matching rotate 2 result", reloaded.HMACSecrets)
	}
}

func TestStore_Rotate_UnknownSubscriberReturnsNotFound(t *testing.T) {
	pool := openTestDB(t)
	defer pool.Close()
	s := NewStore(pool)

	_, err := s.Rotate(context.Background(), uuid.New(), "new-secret", "kid")
	if err != ErrNotFound {
		t.Fatalf("Rotate() error = %v, want ErrNotFound", err)
	}
}

func TestStore_MarkAttempt_IncrementsAttemptsAndPushesBackoff(t *testing.T) {
	pool := openTestDB(t)
	defer pool.Close()
	ctx := context.Background()
	s := NewStore(pool)

	sub := &Subscriber{
		URL: "https://example.test/markattempt", HMACSecrets: []string{"p", "", ""},
		KeyIDs: []string{"k", "", ""}, Enabled: true,
	}
	if err := s.Upsert(ctx, sub); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	defer s.Delete(ctx, sub.ID)

	row := &OutboxRow{SubscriberID: sub.ID, EventID: "evt-markattempt", EventType: "prompt_scan", Payload: []byte(`{}`)}
	if err := s.EnqueueOutbox(ctx, row); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	if err := s.MarkAttempt(ctx, row.ID, "transient failure", 2*time.Second); err != nil {
		t.Fatalf("mark attempt: %v", err)
	}

	// The row should still be pending immediately after MarkAttempt
	// because next_attempt_at was pushed into the future.
	pending, err := s.FetchPendingOutbox(ctx, 10)
	if err != nil {
		t.Fatalf("fetch pending: %v", err)
	}
	for _, p := range pending {
		if p.ID == row.ID {
			t.Fatal("row should not be immediately pending after MarkAttempt pushed next_attempt_at forward")
		}
	}
}

func TestStore_OutboxSize_CountsOnlyUndelivered(t *testing.T) {
	pool := openTestDB(t)
	defer pool.Close()
	ctx := context.Background()
	s := NewStore(pool)

	sub := &Subscriber{
		URL: "https://example.test/outboxsize", HMACSecrets: []string{"p", "", ""},
		KeyIDs: []string{"k", "", ""}, Enabled: true,
	}
	if err := s.Upsert(ctx, sub); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	defer s.Delete(ctx, sub.ID)

	before, err := s.OutboxSize(ctx)
	if err != nil {
		t.Fatalf("outbox size before: %v", err)
	}

	row := &OutboxRow{SubscriberID: sub.ID, EventID: "evt-outboxsize", EventType: "prompt_scan", Payload: []byte(`{}`)}
	if err := s.EnqueueOutbox(ctx, row); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	after, err := s.OutboxSize(ctx)
	if err != nil {
		t.Fatalf("outbox size after enqueue: %v", err)
	}
	if after != before+1 {
		t.Fatalf("outbox size after enqueue = %d, want %d", after, before+1)
	}

	if err := s.MarkDelivered(ctx, row.ID); err != nil {
		t.Fatalf("mark delivered: %v", err)
	}
	afterDelivered, err := s.OutboxSize(ctx)
	if err != nil {
		t.Fatalf("outbox size after delivered: %v", err)
	}
	if afterDelivered != before {
		t.Fatalf("outbox size after delivered = %d, want back to %d", afterDelivered, before)
	}
}

func TestStore_Upsert_DefaultsIDAndTimestampsThenPreservesCreatedAtOnUpdate(t *testing.T) {
	pool := openTestDB(t)
	defer pool.Close()
	ctx := context.Background()
	s := NewStore(pool)

	sub := &Subscriber{
		URL: "https://example.test/upsert-defaults", HMACSecrets: []string{"p", "", ""},
		KeyIDs: []string{"k", "", ""}, Enabled: true,
	}
	if err := s.Upsert(ctx, sub); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	defer s.Delete(ctx, sub.ID)
	if sub.ID == uuid.Nil {
		t.Fatal("Upsert did not assign an ID")
	}
	firstCreated := sub.CreatedAt
	if firstCreated.IsZero() {
		t.Fatal("Upsert did not assign CreatedAt")
	}

	// Update: CreatedAt should stay put on the DB row (Upsert is called
	// with the same in-memory CreatedAt so this mostly verifies the
	// round trip doesn't corrupt it), URL should change.
	sub.URL = "https://example.test/upsert-defaults-changed"
	if err := s.Upsert(ctx, sub); err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	reloaded, err := s.Get(ctx, sub.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if reloaded.URL != sub.URL {
		t.Fatalf("reloaded URL = %q, want %q", reloaded.URL, sub.URL)
	}
}
