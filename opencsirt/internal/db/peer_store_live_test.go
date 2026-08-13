package db

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestPeerStoreLive_InsertGetUpdateHandshake(t *testing.T) {
	pool := liveDB(t)
	s := NewPeerStore(pool)
	ctx := context.Background()

	p := &PeerCSIRT{
		Name:               "Live Peer " + uuid.NewString(),
		Jurisdiction:       "EU",
		ContactEndpoint:    "https://peer.example.test",
		Registry:           "tf-csirt",
		Trust:              "verified",
		Ed25519Fingerprint: "abc123",
	}
	if err := s.Insert(ctx, p); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM peer_csirts WHERE id = $1`, p.ID) })

	got, err := s.Get(ctx, p.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != p.Name || got.Registry != p.Registry || got.Trust != p.Trust {
		t.Errorf("Get round-trip mismatch: got %+v", got)
	}
	if got.LastHandshakeAt != nil {
		t.Errorf("Get LastHandshakeAt = %v, want nil before any handshake", got.LastHandshakeAt)
	}

	if err := s.UpdateHandshakeAt(ctx, p.ID); err != nil {
		t.Fatalf("UpdateHandshakeAt: %v", err)
	}
	got, err = s.Get(ctx, p.ID)
	if err != nil {
		t.Fatalf("Get after handshake: %v", err)
	}
	if got.LastHandshakeAt == nil {
		t.Error("UpdateHandshakeAt did not stamp last_handshake_at")
	}

	if err := s.UpdateHandshakeAt(ctx, uuid.New()); err != ErrNotFound {
		t.Errorf("UpdateHandshakeAt(missing) = %v, want ErrNotFound", err)
	}
}

func TestPeerStoreLive_GetMissingReturnsErrNotFound(t *testing.T) {
	pool := liveDB(t)
	s := NewPeerStore(pool)

	_, err := s.Get(context.Background(), uuid.New())
	if err != ErrNotFound {
		t.Fatalf("Get(missing) error = %v, want ErrNotFound", err)
	}
}

func TestPeerStoreLive_List(t *testing.T) {
	pool := liveDB(t)
	s := NewPeerStore(pool)
	ctx := context.Background()

	tag := uuid.NewString()
	var ids []uuid.UUID
	for _, n := range []string{"B-" + tag, "A-" + tag} {
		p := &PeerCSIRT{Name: n, Jurisdiction: "EU", ContactEndpoint: "https://x.test", Registry: "other", Trust: "pending", Ed25519Fingerprint: "f"}
		if err := s.Insert(ctx, p); err != nil {
			t.Fatalf("Insert: %v", err)
		}
		ids = append(ids, p.ID)
	}
	t.Cleanup(func() {
		for _, id := range ids {
			_, _ = pool.Exec(context.Background(), `DELETE FROM peer_csirts WHERE id = $1`, id)
		}
	})

	items, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var aIdx, bIdx = -1, -1
	for idx, it := range items {
		if it.Name == "A-"+tag {
			aIdx = idx
		}
		if it.Name == "B-"+tag {
			bIdx = idx
		}
	}
	if aIdx == -1 || bIdx == -1 {
		t.Fatalf("List did not return both inserted peers: %+v", items)
	}
	if aIdx > bIdx {
		t.Errorf("List not ordered by name ASC: A at %d, B at %d", aIdx, bIdx)
	}
}

func TestEscalationStoreLive_InsertListForIncidentAndDuplicate(t *testing.T) {
	pool := liveDB(t)
	incidents := NewIncidentStore(pool)
	peers := NewPeerStore(pool)
	s := NewEscalationStore(pool)
	ctx := context.Background()

	inc := &Incident{Source: "manual", Severity: "high", Title: "escalation-target"}
	if err := incidents.Insert(ctx, inc); err != nil {
		t.Fatalf("Insert incident: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM incidents WHERE id = $1`, inc.ID) })

	peer := &PeerCSIRT{Name: "Escalation Peer " + uuid.NewString(), Jurisdiction: "EU", ContactEndpoint: "https://x.test", Registry: "other", Trust: "pending", Ed25519Fingerprint: "f"}
	if err := peers.Insert(ctx, peer); err != nil {
		t.Fatalf("Insert peer: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM peer_csirts WHERE id = $1`, peer.ID) })

	e := &Escalation{IncidentID: inc.ID, PeerID: peer.ID, Response: map[string]any{"ack": true}}
	if err := s.Insert(ctx, e); err != nil {
		t.Fatalf("Insert escalation: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM escalations WHERE incident_id = $1 AND peer_id = $2`, inc.ID, peer.ID)
	})

	// (incident_id, peer_id) is UNIQUE with ON CONFLICT DO NOTHING: a second
	// insert for the same pair must not error and must not create a duplicate row.
	dup := &Escalation{IncidentID: inc.ID, PeerID: peer.ID}
	if err := s.Insert(ctx, dup); err != nil {
		t.Fatalf("Insert duplicate escalation: %v", err)
	}

	list, err := s.ListForIncident(ctx, inc.ID)
	if err != nil {
		t.Fatalf("ListForIncident: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("ListForIncident returned %d rows, want 1 (duplicate must be a no-op)", len(list))
	}
	if list[0].Response["ack"] != true {
		t.Errorf("ListForIncident Response did not round-trip: %+v", list[0].Response)
	}
}
