package rules

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ErrNotFound is returned by Repo.Get / Repo.Delete when the id is unknown.
var ErrNotFound = errors.New("rule not found")

// Repo is the storage abstraction the Service uses. *db.RuleStore from
// internal/db/rule_store.go implements this; MemoryRepo (below) is the
// drop-in implementation when OPENSCRUB_DB_URL is empty.
type Repo interface {
	Insert(ctx context.Context, r Rule) (Rule, error)
	Get(ctx context.Context, id uuid.UUID) (Rule, error)
	Delete(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context, kind Type, limit, offset int) ([]Rule, error)
	DeleteExpired(ctx context.Context, now time.Time) ([]Rule, error)
	Count(ctx context.Context) (int, error)
}

// MemoryRepo is a process-local repository used when no DB is configured.
type MemoryRepo struct {
	mu    sync.Mutex
	rules map[uuid.UUID]Rule
}

// NewMemoryRepo returns an empty in-memory repo.
func NewMemoryRepo() *MemoryRepo {
	return &MemoryRepo{rules: make(map[uuid.UUID]Rule)}
}

// Insert stores a copy.
func (m *MemoryRepo) Insert(_ context.Context, r Rule) (Rule, error) {
	if r.CIDR != "" {
		prefix, err := ParseCIDR(r.CIDR)
		if err != nil {
			return Rule{}, err
		}
		r.CIDR = prefix.String()
	}
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	if r.ExpiresAt.IsZero() {
		r.ExpiresAt = r.CreatedAt.Add(time.Duration(r.TTLSeconds) * time.Second)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rules[r.ID] = r
	return r, nil
}

// Get returns the rule for id.
func (m *MemoryRepo) Get(_ context.Context, id uuid.UUID) (Rule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rules[id]
	if !ok {
		return Rule{}, ErrNotFound
	}
	return r, nil
}

// Delete removes id; returns ErrNotFound if absent.
func (m *MemoryRepo) Delete(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.rules[id]; !ok {
		return ErrNotFound
	}
	delete(m.rules, id)
	return nil
}

// List returns rules ordered by (created_at DESC, id DESC) so identical
// timestamps yield a stable total order across pages. Pagination is
// applied AFTER sorting: rows in [offset, offset+limit) are returned.
func (m *MemoryRepo) List(_ context.Context, kind Type, limit, offset int) ([]Rule, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Rule, 0, len(m.rules))
	for _, r := range m.rules {
		if kind != "" && r.Type != kind {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			// id DESC — bytes.Compare on the 16-byte UUID gives a
			// deterministic tiebreaker that matches the Postgres
			// ORDER BY id DESC pgtype/uuid comparator.
			a, b := out[i].ID, out[j].ID
			for k := 0; k < len(a); k++ {
				if a[k] != b[k] {
					return a[k] > b[k]
				}
			}
			return false
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	if offset >= len(out) {
		return []Rule{}, nil
	}
	out = out[offset:]
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// DeleteExpired removes and returns rules whose expires_at <= now.
func (m *MemoryRepo) DeleteExpired(_ context.Context, now time.Time) ([]Rule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var expired []Rule
	for id, r := range m.rules {
		if r.IsExpired(now) {
			expired = append(expired, r)
			delete(m.rules, id)
		}
	}
	return expired, nil
}

// Count returns the in-memory rule count.
func (m *MemoryRepo) Count(_ context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.rules), nil
}
