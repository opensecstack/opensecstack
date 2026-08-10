package db

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestOutboxStoreEnqueue_DefaultsAppliedBeforeExecFails(t *testing.T) {
	s := NewOutboxStore(unreachablePool(t))
	e := &OutboxEntry{EventType: "incident.opened"}

	err := s.Enqueue(context.Background(), e)
	if err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
	if e.ID == uuid.Nil {
		t.Error("Enqueue did not assign a default ID before failing")
	}
	if e.EventID == "" {
		t.Error("Enqueue did not assign a default EventID before failing")
	}
	if e.State != "pending" {
		t.Errorf("Enqueue State = %q, want default %q", e.State, "pending")
	}
	if e.CreatedAt.IsZero() {
		t.Error("Enqueue did not assign a default CreatedAt before failing")
	}
}

func TestOutboxStoreEnqueue_PreservesCallerSuppliedFields(t *testing.T) {
	s := NewOutboxStore(unreachablePool(t))
	id := uuid.New()
	e := &OutboxEntry{
		ID:        id,
		EventID:   "explicit-event-id",
		EventType: "incident.opened",
		State:     "sending",
	}
	_ = s.Enqueue(context.Background(), e)

	if e.ID != id {
		t.Errorf("Enqueue overwrote caller-supplied ID: got %s want %s", e.ID, id)
	}
	if e.EventID != "explicit-event-id" {
		t.Errorf("Enqueue overwrote caller-supplied EventID: got %s", e.EventID)
	}
	if e.State != "sending" {
		t.Errorf("Enqueue overwrote caller-supplied State: got %s", e.State)
	}
}

func TestOutboxStoreEnqueue_InvalidPayloadFailsBeforeExec(t *testing.T) {
	s := NewOutboxStore(unreachablePool(t))
	// channels are not JSON-marshalable; this must fail at json.Marshal,
	// distinctly from the DB-connection failure exercised elsewhere.
	e := &OutboxEntry{
		EventType: "incident.opened",
		Payload:   map[string]any{"bad": make(chan int)},
	}
	err := s.Enqueue(context.Background(), e)
	if err == nil {
		t.Fatal("expected a JSON marshal error, got nil")
	}
}

func TestOutboxStorePending_PropagatesError(t *testing.T) {
	s := NewOutboxStore(unreachablePool(t))
	rows, err := s.Pending(context.Background(), 10)
	if err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
	if rows != nil {
		t.Errorf("Pending returned non-nil rows alongside an error: %+v", rows)
	}
}

func TestOutboxStoreMarkSending_PropagatesError(t *testing.T) {
	s := NewOutboxStore(unreachablePool(t))
	if err := s.MarkSending(context.Background(), uuid.New(), 1); err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
}

func TestOutboxStoreMarkSent_PropagatesError(t *testing.T) {
	s := NewOutboxStore(unreachablePool(t))
	if err := s.MarkSent(context.Background(), uuid.New()); err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
}

func TestOutboxStoreMarkFailed_PropagatesError(t *testing.T) {
	s := NewOutboxStore(unreachablePool(t))
	if err := s.MarkFailed(context.Background(), uuid.New(), "boom"); err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
}

func TestOutboxStoreRequeueSending_PropagatesError(t *testing.T) {
	s := NewOutboxStore(unreachablePool(t))
	n, err := s.RequeueSending(context.Background())
	if err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
	if n != 0 {
		t.Errorf("RequeueSending count = %d alongside an error, want 0", n)
	}
}

func TestOutboxStorePendingCount_PropagatesError(t *testing.T) {
	s := NewOutboxStore(unreachablePool(t))
	if _, err := s.PendingCount(context.Background()); err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
}

func TestOutboxStoreFailedCount_PropagatesError(t *testing.T) {
	s := NewOutboxStore(unreachablePool(t))
	if _, err := s.FailedCount(context.Background()); err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
}
