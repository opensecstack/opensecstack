package db

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestOutboxStoreLive_EnqueueDuplicateEventIDIsNoOp(t *testing.T) {
	pool := liveDB(t)
	s := NewOutboxStore(pool)
	ctx := context.Background()

	eventID := "evt-" + uuid.NewString()
	e := &OutboxEntry{EventID: eventID, EventType: "advisory.published", TargetType: "advisory", Payload: map[string]any{"a": 1}}
	if err := s.Enqueue(ctx, e); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM citadel_outbox WHERE event_id = $1`, eventID)
	})

	dup := &OutboxEntry{EventID: eventID, EventType: "advisory.published", TargetType: "advisory"}
	if err := s.Enqueue(ctx, dup); err != nil {
		t.Fatalf("Enqueue duplicate event_id: %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM citadel_outbox WHERE event_id = $1`, eventID).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("duplicate event_id created %d rows, want 1", count)
	}
}

func TestOutboxStoreLive_PendingFetchesAndOrders(t *testing.T) {
	pool := liveDB(t)
	s := NewOutboxStore(pool)
	ctx := context.Background()

	tag := uuid.NewString()
	var ids []uuid.UUID
	for i := 0; i < 3; i++ {
		e := &OutboxEntry{EventID: "evt-" + tag + "-" + uuid.NewString(), EventType: "t", TargetType: "incident"}
		if err := s.Enqueue(ctx, e); err != nil {
			t.Fatalf("Enqueue[%d]: %v", i, err)
		}
		ids = append(ids, e.ID)
	}
	t.Cleanup(func() {
		for _, id := range ids {
			_, _ = pool.Exec(context.Background(), `DELETE FROM citadel_outbox WHERE id = $1`, id)
		}
	})

	entries, err := s.Pending(ctx, 500)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	var found int
	for _, e := range entries {
		for _, id := range ids {
			if e.ID == id {
				found++
			}
		}
	}
	if found != 3 {
		t.Errorf("Pending returned %d of our 3 enqueued rows", found)
	}

	// limit<=0 and limit>200 both fall back to the default of 50.
	if _, err := s.Pending(ctx, 0); err != nil {
		t.Errorf("Pending(0): %v", err)
	}
	if _, err := s.Pending(ctx, 1000); err != nil {
		t.Errorf("Pending(1000): %v", err)
	}
}

func TestOutboxStoreLive_MarkSendingSentFailedRequeue(t *testing.T) {
	pool := liveDB(t)
	s := NewOutboxStore(pool)
	ctx := context.Background()

	e := &OutboxEntry{EventID: "evt-" + uuid.NewString(), EventType: "t", TargetType: "incident"}
	if err := s.Enqueue(ctx, e); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM citadel_outbox WHERE id = $1`, e.ID) })

	if err := s.MarkSending(ctx, e.ID, 1); err != nil {
		t.Fatalf("MarkSending: %v", err)
	}
	// A second MarkSending finds no row still in 'pending': explicit error.
	if err := s.MarkSending(ctx, e.ID, 2); err == nil {
		t.Error("MarkSending on an already-sending row: expected an error, got nil")
	}

	if err := s.MarkSent(ctx, e.ID); err != nil {
		t.Fatalf("MarkSent: %v", err)
	}
	if err := s.MarkSent(ctx, uuid.New()); err != ErrNotFound {
		t.Errorf("MarkSent(missing) = %v, want ErrNotFound", err)
	}

	e2 := &OutboxEntry{EventID: "evt-" + uuid.NewString(), EventType: "t", TargetType: "incident"}
	if err := s.Enqueue(ctx, e2); err != nil {
		t.Fatalf("Enqueue e2: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM citadel_outbox WHERE id = $1`, e2.ID) })

	if err := s.MarkFailed(ctx, e2.ID, "boom"); err != nil {
		t.Fatalf("MarkFailed: %v", err)
	}

	failedCount, err := s.FailedCount(ctx)
	if err != nil {
		t.Fatalf("FailedCount: %v", err)
	}
	if failedCount < 1 {
		t.Errorf("FailedCount = %d, want >= 1", failedCount)
	}

	e3 := &OutboxEntry{EventID: "evt-" + uuid.NewString(), EventType: "t", TargetType: "incident"}
	if err := s.Enqueue(ctx, e3); err != nil {
		t.Fatalf("Enqueue e3: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM citadel_outbox WHERE id = $1`, e3.ID) })
	if err := s.MarkSending(ctx, e3.ID, 1); err != nil {
		t.Fatalf("MarkSending e3: %v", err)
	}

	n, err := s.RequeueSending(ctx)
	if err != nil {
		t.Fatalf("RequeueSending: %v", err)
	}
	if n < 1 {
		t.Errorf("RequeueSending affected %d rows, want >= 1", n)
	}

	pendingCount, err := s.PendingCount(ctx)
	if err != nil {
		t.Fatalf("PendingCount: %v", err)
	}
	if pendingCount < 1 {
		t.Errorf("PendingCount = %d, want >= 1 after requeue", pendingCount)
	}
}
