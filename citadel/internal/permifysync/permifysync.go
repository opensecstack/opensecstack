// Package permifysync builds and maintains the local snapshot MARSHAL Gate 2
// (AuthZ) reads instead of calling Permify live per-request. Gate 2 runs in
// the hot path of every governed action across the ecosystem at
// ~microsecond latency, so a synchronous Permify round-trip per Kerkese is
// not acceptable — see adrs/007-permify-gate2-snapshot.md.
//
// The pieces:
//   - RoleAction / Snapshot: the (role, action_type) -> allowed shape Gate 2
//     reads, held in memory and safe for concurrent reads.
//   - MatrixFetcher / PermifyFetcher: pulls the current role -> action_type
//     coverage from Permify.
//   - SnapshotStore / PgSnapshotStore: persists the fetched matrix to the
//     permify_role_action_snapshot table (migrations/005), so a restart
//     doesn't start from a cold, "nothing known" snapshot.
//   - Syncer: a time.Ticker-driven loop tying the above together, run as a
//     background goroutine started alongside the HTTP server.
//
// Mapping decision (see FetchRoleActionMatrix's doc comment for the full
// rationale): sinauth's Permify schema (sinauth/permify/schema.perm) does
// not yet model CITADEL's action-type vocabulary at all — it covers
// organization/group/client_role membership, not "role R may perform
// governed action type T". Fabricating that mapping from data Permify
// doesn't actually assert would be dishonest and would let a
// Permify-snapshot check silently authorize things no one configured. This
// package therefore syncs the real (currently empty) coverage Permify
// provides rather than inventing coverage — Gate 2's unconditionally
// enforced rbacMap check remains the actual safety net; the Permify
// snapshot only ever adds an opt-in, additive signal on top of it once the
// schema is extended in a later phase.
package permifysync

import (
	"context"
	"sync"
)

// RoleAction identifies a single (role, action_type) pair — the same
// vocabulary as internal/marshal's Kerkese.Actor.Role / Kerkese.Action.Type
// and the rbacMap it falls back to.
type RoleAction struct {
	Role       string
	ActionType string
}

// Snapshot is the in-memory copy of permify_role_action_snapshot that Gate 2
// reads synchronously. It is refreshed wholesale by Syncer on each
// successful fetch and is safe for concurrent use.
type Snapshot struct {
	mu   sync.RWMutex
	data map[RoleAction]bool
}

// NewSnapshot returns an empty Snapshot — the correct starting state before
// the first successful sync (or if Permify has never asserted anything for
// a given role/action_type pair).
func NewSnapshot() *Snapshot {
	return &Snapshot{data: make(map[RoleAction]bool)}
}

// Allowed reports what the Permify-derived snapshot currently says about
// role performing actionType.
//
//   - known=false means the snapshot has no opinion — either it hasn't been
//     synced yet, or Permify's schema doesn't cover this (role, action_type)
//     pair. Callers (Gate 2) should fall back to another source (rbacMap)
//     rather than treating this as an explicit denial.
//   - known=true means Permify explicitly asserted allowed/denied for this
//     pair; allowed carries that verdict.
func (s *Snapshot) Allowed(role, actionType string) (allowed bool, known bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	allowed, known = s.data[RoleAction{Role: role, ActionType: actionType}]
	return allowed, known
}

// Len returns how many (role, action_type) facts the snapshot currently
// holds. Mainly useful for tests and observability (e.g. logging how much
// coverage a sync produced).
func (s *Snapshot) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.data)
}

// replace atomically swaps the snapshot's contents. Called only by Syncer
// after a successful fetch — a failed fetch must never call this, so the
// previous (possibly stale, but real) snapshot stays in place.
func (s *Snapshot) replace(data map[RoleAction]bool) {
	if data == nil {
		data = make(map[RoleAction]bool)
	}
	s.mu.Lock()
	s.data = data
	s.mu.Unlock()
}

// MatrixFetcher fetches the current role -> action_type coverage Permify
// asserts. Implementations: PermifyFetcher (real, see permify_fetcher.go).
type MatrixFetcher interface {
	FetchRoleActionMatrix(ctx context.Context) (map[RoleAction]bool, error)
}

// SnapshotStore persists the synced matrix so a CITADEL restart starts from
// the last-known-good snapshot rather than an empty one. Implementations:
// PgSnapshotStore (real, see store.go).
type SnapshotStore interface {
	// ReplaceSnapshot atomically replaces the persisted snapshot with rows.
	// Called only after a successful fetch.
	ReplaceSnapshot(ctx context.Context, rows map[RoleAction]bool) error
	// LoadSnapshot reads the persisted snapshot back, e.g. at startup before
	// the first sync tick has run.
	LoadSnapshot(ctx context.Context) (map[RoleAction]bool, error)
}
