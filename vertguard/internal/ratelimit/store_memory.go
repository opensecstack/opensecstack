package ratelimit

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// MemoryOverrideStore is an in-memory OverrideStore. Used for tests and
// as the dev-mode fallback when no DB is configured.
type MemoryOverrideStore struct {
	mu      sync.RWMutex
	entries map[string]Override // keyed by "kind:value"
	now     func() time.Time
}

// NewMemoryOverrideStore returns an empty MemoryOverrideStore.
func NewMemoryOverrideStore() *MemoryOverrideStore {
	return &MemoryOverrideStore{
		entries: map[string]Override{},
		now:     time.Now,
	}
}

// List returns active entries (expired rows are filtered) sorted by
// CreatedAt descending — newest first, matching the DB-backed store.
func (s *MemoryOverrideStore) List(_ context.Context) ([]Override, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := s.now()
	out := make([]Override, 0, len(s.entries))
	for _, o := range s.entries {
		if !o.IsActive(now) {
			continue
		}
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

// Add inserts or replaces an entry. Auto-fills CreatedAt if zero.
func (s *MemoryOverrideStore) Add(_ context.Context, o Override) error {
	if o.Kind != KindSub && o.Kind != KindIP {
		return errors.New("ratelimit: invalid kind")
	}
	if o.Value == "" {
		return errors.New("ratelimit: empty value")
	}
	if o.CreatedAt.IsZero() {
		o.CreatedAt = s.now()
	}
	s.mu.Lock()
	s.entries[o.Kind+":"+o.Value] = o
	s.mu.Unlock()
	return nil
}

// Remove deletes by (kind, value). No-op if missing.
func (s *MemoryOverrideStore) Remove(_ context.Context, kind, value string) error {
	s.mu.Lock()
	delete(s.entries, kind+":"+value)
	s.mu.Unlock()
	return nil
}
