package handlers

import (
	"context"
	"testing"
)

// TestIssueAndConsumeSSETicket_Success_SingleUse exercises the unexported
// issueSSETicket/consumeSSETicket helpers directly: a ticket must be
// consumable exactly once, and consuming deletes the row so replay fails.
func TestIssueAndConsumeSSETicket_Success_SingleUse(t *testing.T) {
	pool := NewTestDBPool(t)
	username := "sse_" + RandomSuffix()
	CleanupUserByUsername(t, pool, username)

	ticket, err := issueSSETicket(context.Background(), pool, username)
	if err != nil {
		t.Fatalf("issueSSETicket: %v", err)
	}
	if ticket == "" {
		t.Fatal("expected a non-empty ticket")
	}

	gotUsername, ok := consumeSSETicket(context.Background(), pool, ticket)
	if !ok {
		t.Fatal("expected the freshly issued ticket to be consumable")
	}
	if gotUsername != username {
		t.Errorf("expected username %q, got %q", username, gotUsername)
	}

	// Replay: the ticket was deleted on first consumption.
	_, ok2 := consumeSSETicket(context.Background(), pool, ticket)
	if ok2 {
		t.Error("expected replaying an already-consumed ticket to fail")
	}
}

func TestConsumeSSETicket_Unknown_Fails(t *testing.T) {
	pool := NewTestDBPool(t)
	_, ok := consumeSSETicket(context.Background(), pool, "no-such-ticket-"+RandomSuffix())
	if ok {
		t.Error("expected an unknown ticket to fail consumption")
	}
}

func TestConsumeSSETicket_Expired_Fails(t *testing.T) {
	pool := NewTestDBPool(t)
	username := "sse_" + RandomSuffix()
	CleanupUserByUsername(t, pool, username)

	ticket := "expired_" + RandomSuffix()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO sse_tickets (ticket, username, expires_at) VALUES ($1,$2, now() - interval '1 second')`,
		ticket, username,
	); err != nil {
		t.Fatalf("insert expired ticket: %v", err)
	}

	_, ok := consumeSSETicket(context.Background(), pool, ticket)
	if ok {
		t.Error("expected an expired ticket to fail consumption")
	}
}
