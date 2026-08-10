package db

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestPeerStoreInsert_DefaultsAppliedBeforeExecFails(t *testing.T) {
	s := NewPeerStore(unreachablePool(t))
	p := &PeerCSIRT{Name: "CERT-X", Jurisdiction: "EU"}

	err := s.Insert(context.Background(), p)
	if err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
	if p.ID == uuid.Nil {
		t.Error("Insert did not assign a default ID before failing")
	}
	if p.CreatedAt.IsZero() {
		t.Error("Insert did not stamp CreatedAt before failing")
	}
}

func TestPeerStoreInsert_PreservesCallerSuppliedID(t *testing.T) {
	s := NewPeerStore(unreachablePool(t))
	id := uuid.New()
	p := &PeerCSIRT{ID: id, Name: "CERT-X"}
	_ = s.Insert(context.Background(), p)

	if p.ID != id {
		t.Errorf("Insert overwrote caller-supplied ID: got %s want %s", p.ID, id)
	}
}

func TestPeerStoreGet_PropagatesConnectionError(t *testing.T) {
	s := NewPeerStore(unreachablePool(t))
	_, err := s.Get(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
	if err == ErrNotFound {
		t.Error("a connection error must not be mapped to ErrNotFound")
	}
}

func TestPeerStoreUpdateHandshakeAt_PropagatesError(t *testing.T) {
	s := NewPeerStore(unreachablePool(t))
	if err := s.UpdateHandshakeAt(context.Background(), uuid.New()); err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
}

func TestPeerStoreList_PropagatesError(t *testing.T) {
	s := NewPeerStore(unreachablePool(t))
	peers, err := s.List(context.Background())
	if err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
	if peers != nil {
		t.Errorf("List returned non-nil peers alongside an error: %+v", peers)
	}
}

func TestEscalationStoreInsert_DefaultsAppliedBeforeExecFails(t *testing.T) {
	s := NewEscalationStore(unreachablePool(t))
	e := &Escalation{IncidentID: uuid.New(), PeerID: uuid.New()}

	err := s.Insert(context.Background(), e)
	if err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
	if e.ID == uuid.Nil {
		t.Error("Insert did not assign a default ID before failing")
	}
	if e.SentAt.IsZero() {
		t.Error("Insert did not assign a default SentAt before failing")
	}
	if e.Response == nil {
		t.Error("Insert did not default nil Response to an empty map before failing")
	}
}

func TestEscalationStoreInsert_InvalidResponseFailsBeforeExec(t *testing.T) {
	s := NewEscalationStore(unreachablePool(t))
	e := &Escalation{
		IncidentID: uuid.New(), PeerID: uuid.New(),
		Response: map[string]any{"bad": make(chan int)},
	}
	if err := s.Insert(context.Background(), e); err == nil {
		t.Fatal("expected a JSON marshal error, got nil")
	}
}

func TestEscalationStoreListForIncident_PropagatesError(t *testing.T) {
	s := NewEscalationStore(unreachablePool(t))
	escs, err := s.ListForIncident(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
	if escs != nil {
		t.Errorf("ListForIncident returned non-nil escalations alongside an error: %+v", escs)
	}
}
