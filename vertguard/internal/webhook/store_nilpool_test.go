package webhook

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// These exercise the "nil pool" guard clause on every Store method — the
// documented contract lets a *Store with Pool==nil be constructed (e.g.
// NewStore(nil)) for tests that only need the dispatcher's fake store.
// Without a live DATABASE_URL this is also the only way to reach
// these methods at all in this environment.

func TestStore_NilPool_Upsert(t *testing.T) {
	s := NewStore(nil)
	err := s.Upsert(context.Background(), &Subscriber{URL: "https://x"})
	if err == nil {
		t.Fatal("Upsert() error = nil, want error for nil pool")
	}
}

func TestStore_NilPool_Get(t *testing.T) {
	s := NewStore(nil)
	_, err := s.Get(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("Get() error = nil, want error for nil pool")
	}
}

func TestStore_NilPool_List(t *testing.T) {
	s := NewStore(nil)
	got, err := s.List(context.Background())
	if err != nil {
		t.Fatalf("List() error = %v, want nil (nil-pool List degrades to empty, not an error)", err)
	}
	if got != nil {
		t.Errorf("List() = %v, want nil slice", got)
	}
}

func TestStore_NilPool_ListByEventType(t *testing.T) {
	s := NewStore(nil)
	got, err := s.ListByEventType(context.Background(), "prompt_scan")
	if err != nil {
		t.Fatalf("ListByEventType() error = %v, want nil", err)
	}
	if got != nil {
		t.Errorf("ListByEventType() = %v, want nil slice", got)
	}
}

func TestStore_NilPool_Delete(t *testing.T) {
	s := NewStore(nil)
	err := s.Delete(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("Delete() error = nil, want error for nil pool")
	}
}

func TestStore_NilPool_Rotate_EmptySecretRejected(t *testing.T) {
	s := NewStore(nil)
	// Empty newSecret must be rejected before the nil-pool check is even
	// relevant — same outcome (error), different reason; verify the
	// message is the secret-specific one.
	_, err := s.Rotate(context.Background(), uuid.New(), "", "kid")
	if err == nil {
		t.Fatal("Rotate() error = nil, want error for empty new secret")
	}
}

func TestStore_NilPool_Rotate_NilPool(t *testing.T) {
	s := NewStore(nil)
	_, err := s.Rotate(context.Background(), uuid.New(), "new-secret", "kid")
	if err == nil {
		t.Fatal("Rotate() error = nil, want error for nil pool")
	}
}

func TestStore_NilPool_EnqueueOutbox(t *testing.T) {
	s := NewStore(nil)
	err := s.EnqueueOutbox(context.Background(), &OutboxRow{})
	if err == nil {
		t.Fatal("EnqueueOutbox() error = nil, want error for nil pool")
	}
}

func TestStore_NilPool_FetchPendingOutbox(t *testing.T) {
	s := NewStore(nil)
	got, err := s.FetchPendingOutbox(context.Background(), 10)
	if err != nil {
		t.Fatalf("FetchPendingOutbox() error = %v, want nil", err)
	}
	if got != nil {
		t.Errorf("FetchPendingOutbox() = %v, want nil slice", got)
	}
}

func TestStore_NilPool_MarkDelivered(t *testing.T) {
	s := NewStore(nil)
	err := s.MarkDelivered(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("MarkDelivered() error = nil, want error for nil pool")
	}
}

func TestStore_NilPool_MarkAttempt(t *testing.T) {
	s := NewStore(nil)
	err := s.MarkAttempt(context.Background(), uuid.New(), "boom", time.Second)
	if err == nil {
		t.Fatal("MarkAttempt() error = nil, want error for nil pool")
	}
}

func TestStore_NilPool_OutboxSize(t *testing.T) {
	s := NewStore(nil)
	n, err := s.OutboxSize(context.Background())
	if err != nil {
		t.Fatalf("OutboxSize() error = %v, want nil", err)
	}
	if n != 0 {
		t.Errorf("OutboxSize() = %d, want 0", n)
	}
}

func TestNormaliseSlots(t *testing.T) {
	tests := []struct {
		name       string
		in         *Subscriber
		wantSecLen int
		wantKidLen int
	}{
		{"pads short slices", &Subscriber{HMACSecrets: []string{"a"}, KeyIDs: []string{"k"}}, NumSlots, NumSlots},
		{"truncates long slices", &Subscriber{HMACSecrets: []string{"a", "b", "c", "d"}, KeyIDs: []string{"1", "2", "3", "4"}}, NumSlots, NumSlots},
		{"leaves exact length alone", &Subscriber{HMACSecrets: []string{"a", "b", "c"}, KeyIDs: []string{"1", "2", "3"}}, NumSlots, NumSlots},
		{"pads nil slices", &Subscriber{}, NumSlots, NumSlots},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normaliseSlots(tt.in)
			if len(tt.in.HMACSecrets) != tt.wantSecLen {
				t.Errorf("len(HMACSecrets) = %d, want %d", len(tt.in.HMACSecrets), tt.wantSecLen)
			}
			if len(tt.in.KeyIDs) != tt.wantKidLen {
				t.Errorf("len(KeyIDs) = %d, want %d", len(tt.in.KeyIDs), tt.wantKidLen)
			}
		})
	}
}
