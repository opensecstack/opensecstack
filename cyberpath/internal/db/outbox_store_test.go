//go:build integration

// Integration tests for OutboxStore. Requires CYBERPATH_TEST_DB_URL pointing
// at a fully-migrated cyberpath schema; otherwise skipped.
package db

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func outboxTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("CYBERPATH_TEST_DB_URL")
	if url == "" {
		t.Skip("CYBERPATH_TEST_DB_URL not set; skipping integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// cleanupOutboxRow registers deletion of an outbox row by id.
func cleanupOutboxRow(t *testing.T, pool *pgxpool.Pool, id int64) {
	t.Helper()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM outbox WHERE id = $1`, id)
	})
}

func TestOutboxStore_EnqueueAndDefaults(t *testing.T) {
	pool := outboxTestPool(t)
	ctx := context.Background()
	store := NewOutboxStore(pool)

	e := &OutboxEntry{
		Destination: "citadel",
		EventType:   "lesson.completed",
	}
	id, err := store.Enqueue(ctx, e)
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	cleanupOutboxRow(t, pool, id)

	if id == 0 {
		t.Fatal("Enqueue: id not populated")
	}
	if e.ID != id {
		t.Fatalf("Enqueue: entry.ID not set, got %d want %d", e.ID, id)
	}
	if e.Status != "pending" {
		t.Fatalf("Enqueue: expected default status pending, got %q", e.Status)
	}

	rows, err := store.Claim(ctx, 10)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	found := false
	for _, r := range rows {
		if r.ID == id {
			found = true
			if string(r.Payload) != "{}" {
				t.Fatalf("Enqueue: expected default payload {}, got %s", r.Payload)
			}
			if r.Status != "in_flight" {
				t.Fatalf("Claim: expected status in_flight, got %q", r.Status)
			}
		}
	}
	if !found {
		t.Fatal("Claim: our enqueued row was not claimed")
	}
}

func TestOutboxStore_Create_InvalidDestination(t *testing.T) {
	pool := outboxTestPool(t)
	ctx := context.Background()
	store := NewOutboxStore(pool)

	_, err := store.Enqueue(ctx, &OutboxEntry{
		Destination: "carrier-pigeon",
		EventType:   "x",
	})
	if err == nil {
		t.Fatal("Enqueue with invalid destination: expected CHECK violation, got nil")
	}
}

func TestOutboxStore_Claim_SkipsLockedAndFuture(t *testing.T) {
	pool := outboxTestPool(t)
	ctx := context.Background()
	store := NewOutboxStore(pool)

	// A row scheduled in the future must not be claimed.
	future := &OutboxEntry{Destination: "citadel", EventType: "future.event"}
	futureID, err := store.Enqueue(ctx, future)
	if err != nil {
		t.Fatalf("Enqueue future: %v", err)
	}
	cleanupOutboxRow(t, pool, futureID)
	if _, err := pool.Exec(ctx, `UPDATE outbox SET next_attempt_at = now() + interval '1 hour' WHERE id = $1`, futureID); err != nil {
		t.Fatalf("push next_attempt_at: %v", err)
	}

	ready := &OutboxEntry{Destination: "citadel", EventType: "ready.event"}
	readyID, err := store.Enqueue(ctx, ready)
	if err != nil {
		t.Fatalf("Enqueue ready: %v", err)
	}
	cleanupOutboxRow(t, pool, readyID)

	claimed, err := store.Claim(ctx, 100)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	var sawReady, sawFuture bool
	for _, r := range claimed {
		if r.ID == readyID {
			sawReady = true
		}
		if r.ID == futureID {
			sawFuture = true
		}
	}
	if !sawReady {
		t.Fatal("Claim: ready row was not claimed")
	}
	if sawFuture {
		t.Fatal("Claim: future-scheduled row was claimed early")
	}

	// A second claim must not re-claim the already in_flight row (it is no
	// longer 'pending').
	claimed2, err := store.Claim(ctx, 100)
	if err != nil {
		t.Fatalf("Claim (second pass): %v", err)
	}
	for _, r := range claimed2 {
		if r.ID == readyID {
			t.Fatal("Claim: re-claimed an already in_flight row")
		}
	}
}

func TestOutboxStore_MarkDelivered(t *testing.T) {
	pool := outboxTestPool(t)
	ctx := context.Background()
	store := NewOutboxStore(pool)

	e := &OutboxEntry{Destination: "webhook", EventType: "quiz.completed"}
	id, err := store.Enqueue(ctx, e)
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	cleanupOutboxRow(t, pool, id)

	if err := store.MarkDelivered(ctx, id); err != nil {
		t.Fatalf("MarkDelivered: %v", err)
	}

	var status string
	var deliveredAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT status, delivered_at FROM outbox WHERE id = $1`, id).Scan(&status, &deliveredAt); err != nil {
		t.Fatalf("query: %v", err)
	}
	if status != "delivered" {
		t.Fatalf("expected status delivered, got %q", status)
	}
	if deliveredAt == nil {
		t.Fatal("delivered_at not stamped")
	}

	// MarkDelivered on an unknown id is a silent no-op (no rows matched);
	// the store does not surface "not found" for this UPDATE.
	if err := store.MarkDelivered(ctx, -1); err != nil {
		t.Fatalf("MarkDelivered(unknown id): expected nil, got %v", err)
	}
}

func TestOutboxStore_MarkFailed_BackoffAndDLQ(t *testing.T) {
	pool := outboxTestPool(t)
	ctx := context.Background()
	store := NewOutboxStore(pool)

	e := &OutboxEntry{Destination: "citadel", EventType: "cert.issued"}
	id, err := store.Enqueue(ctx, e)
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	cleanupOutboxRow(t, pool, id)

	if err := store.MarkFailed(ctx, id, "connection refused"); err != nil {
		t.Fatalf("MarkFailed: %v", err)
	}

	var attempts int
	var status, lastErr string
	var nextAttempt time.Time
	if err := pool.QueryRow(ctx, `SELECT attempts, status, last_error, next_attempt_at FROM outbox WHERE id = $1`, id).
		Scan(&attempts, &status, &lastErr, &nextAttempt); err != nil {
		t.Fatalf("query: %v", err)
	}
	if attempts != 1 {
		t.Fatalf("expected attempts=1, got %d", attempts)
	}
	if status != "pending" {
		t.Fatalf("expected status still pending after 1 failure, got %q", status)
	}
	if lastErr != "connection refused" {
		t.Fatalf("last_error mismatch: got %q", lastErr)
	}
	if !nextAttempt.After(time.Now()) {
		t.Fatal("next_attempt_at was not pushed into the future")
	}

	// Drive attempts past the >10 threshold to reach the DLQ.
	for i := 0; i < 10; i++ {
		if err := store.MarkFailed(ctx, id, "still failing"); err != nil {
			t.Fatalf("MarkFailed iteration %d: %v", i, err)
		}
	}
	var finalStatus string
	var finalAttempts int
	if err := pool.QueryRow(ctx, `SELECT status, attempts FROM outbox WHERE id = $1`, id).Scan(&finalStatus, &finalAttempts); err != nil {
		t.Fatalf("query final: %v", err)
	}
	if finalStatus != "dlq" {
		t.Fatalf("expected status dlq after >10 attempts (attempts=%d), got %q", finalAttempts, finalStatus)
	}

	dlq, err := store.DLQ(ctx, 100, 0)
	if err != nil {
		t.Fatalf("DLQ: %v", err)
	}
	foundInDLQ := false
	for _, r := range dlq {
		if r.ID == id {
			foundInDLQ = true
		}
	}
	if !foundInDLQ {
		t.Fatal("DLQ: our row was not listed")
	}

	if err := store.RequeueFromDLQ(ctx, id); err != nil {
		t.Fatalf("RequeueFromDLQ: %v", err)
	}
	var status2 string
	var attempts2 int
	if err := pool.QueryRow(ctx, `SELECT status, attempts FROM outbox WHERE id = $1`, id).Scan(&status2, &attempts2); err != nil {
		t.Fatalf("query after requeue: %v", err)
	}
	if status2 != "pending" {
		t.Fatalf("expected status pending after requeue, got %q", status2)
	}
	if attempts2 != 0 {
		t.Fatalf("expected attempts reset to 0 after requeue, got %d", attempts2)
	}

	// RequeueFromDLQ on a row that's not in 'dlq' status is a no-op (the
	// WHERE clause requires status='dlq').
	if err := store.RequeueFromDLQ(ctx, id); err != nil {
		t.Fatalf("RequeueFromDLQ (already pending): expected nil, got %v", err)
	}
}

func TestOutboxStore_GCDelivered(t *testing.T) {
	pool := outboxTestPool(t)
	ctx := context.Background()
	store := NewOutboxStore(pool)

	old := &OutboxEntry{Destination: "citadel", EventType: "old.event"}
	oldID, err := store.Enqueue(ctx, old)
	if err != nil {
		t.Fatalf("Enqueue old: %v", err)
	}
	cleanupOutboxRow(t, pool, oldID)
	if _, err := pool.Exec(ctx, `
		UPDATE outbox SET status = 'delivered', delivered_at = now() - interval '100 days'
		WHERE id = $1`, oldID); err != nil {
		t.Fatalf("backdate delivered_at: %v", err)
	}

	recent := &OutboxEntry{Destination: "citadel", EventType: "recent.event"}
	recentID, err := store.Enqueue(ctx, recent)
	if err != nil {
		t.Fatalf("Enqueue recent: %v", err)
	}
	cleanupOutboxRow(t, pool, recentID)
	if err := store.MarkDelivered(ctx, recentID); err != nil {
		t.Fatalf("MarkDelivered recent: %v", err)
	}

	n, err := store.GCDelivered(ctx, 90*24*time.Hour)
	if err != nil {
		t.Fatalf("GCDelivered: %v", err)
	}
	if n < 1 {
		t.Fatalf("GCDelivered: expected at least 1 row removed, got %d", n)
	}

	var stillThere int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE id = $1`, oldID).Scan(&stillThere); err != nil {
		t.Fatalf("query old: %v", err)
	}
	if stillThere != 0 {
		t.Fatal("GCDelivered did not remove the old delivered row")
	}

	var recentThere int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE id = $1`, recentID).Scan(&recentThere); err != nil {
		t.Fatalf("query recent: %v", err)
	}
	if recentThere != 1 {
		t.Fatal("GCDelivered incorrectly removed the recent delivered row")
	}
}
