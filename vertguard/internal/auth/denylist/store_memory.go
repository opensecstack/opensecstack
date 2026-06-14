package denylist

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemoryStore is an in-memory Store. Used for tests and as the dev-mode
// fallback when no DB is configured.
type MemoryStore struct {
	mu      sync.RWMutex
	entries map[string]Entry // keyed by "kind:value"
	now     func() time.Time
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		entries: map[string]Entry{},
		now:     time.Now,
	}
}

// List returns the active entries (expired rows are filtered) sorted by
// RevokedAt descending — newest first, matching DB semantics.
func (s *MemoryStore) List(_ context.Context) ([]Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := s.now()
	out := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		if !e.IsActive(now) {
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].RevokedAt.After(out[j].RevokedAt)
	})
	return out, nil
}

// Add inserts or replaces an entry. Auto-fills ID + RevokedAt if zero.
func (s *MemoryStore) Add(_ context.Context, e Entry) error {
	if e.Kind != KindJTI && e.Kind != KindSub {
		return errors.New("denylist: invalid kind")
	}
	if e.Value == "" {
		return errors.New("denylist: empty value")
	}
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	if e.RevokedAt.IsZero() {
		e.RevokedAt = s.now()
	}
	s.mu.Lock()
	s.entries[key(e.Kind, e.Value)] = e
	s.mu.Unlock()
	return nil
}

// Remove deletes by (kind, value). No-op if missing.
func (s *MemoryStore) Remove(_ context.Context, kind, value string) error {
	s.mu.Lock()
	delete(s.entries, key(kind, value))
	s.mu.Unlock()
	return nil
}
