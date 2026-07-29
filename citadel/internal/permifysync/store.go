package permifysync

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgSnapshotStore persists the synced role/action_type matrix to the
// permify_role_action_snapshot table (migrations/005_permify_policy_snapshot.sql).
type PgSnapshotStore struct {
	pool *pgxpool.Pool
}

// NewPgSnapshotStore wraps an existing pgx pool (e.g. db.DB.Pool). It does
// not open its own connection — CITADEL already has one pool for the
// process, shared across stores.
func NewPgSnapshotStore(pool *pgxpool.Pool) *PgSnapshotStore {
	return &PgSnapshotStore{pool: pool}
}

// ReplaceSnapshot atomically replaces the persisted snapshot with rows,
// inside a single transaction so a reader never observes a partially
// cleared table. Called only after a successful Permify fetch — on fetch
// failure, Syncer never calls this, so the previous rows (stale but real)
// stay exactly as they were.
func (s *PgSnapshotStore) ReplaceSnapshot(ctx context.Context, rows map[RoleAction]bool) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("permifysync: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	if _, err := tx.Exec(ctx, `DELETE FROM permify_role_action_snapshot`); err != nil {
		return fmt.Errorf("permifysync: clear snapshot: %w", err)
	}

	batch := &pgx.Batch{}
	for ra, allowed := range rows {
		batch.Queue(
			`INSERT INTO permify_role_action_snapshot (role, action_type, allowed, synced_at)
			 VALUES ($1, $2, $3, now())
			 ON CONFLICT (role, action_type) DO UPDATE
			   SET allowed = EXCLUDED.allowed, synced_at = EXCLUDED.synced_at`,
			ra.Role, ra.ActionType, allowed,
		)
	}
	if batch.Len() > 0 {
		br := tx.SendBatch(ctx, batch)
		for i := 0; i < batch.Len(); i++ {
			if _, err := br.Exec(); err != nil {
				br.Close()
				return fmt.Errorf("permifysync: upsert snapshot row %d: %w", i, err)
			}
		}
		if err := br.Close(); err != nil {
			return fmt.Errorf("permifysync: close batch: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("permifysync: commit snapshot: %w", err)
	}
	return nil
}

// LoadSnapshot reads the persisted snapshot, e.g. at startup so Gate 2 has
// last-known-good data before the first sync tick completes.
func (s *PgSnapshotStore) LoadSnapshot(ctx context.Context) (map[RoleAction]bool, error) {
	rows, err := s.pool.Query(ctx, `SELECT role, action_type, allowed FROM permify_role_action_snapshot`)
	if err != nil {
		return nil, fmt.Errorf("permifysync: load snapshot: %w", err)
	}
	defer rows.Close()

	data := make(map[RoleAction]bool)
	for rows.Next() {
		var ra RoleAction
		var allowed bool
		if err := rows.Scan(&ra.Role, &ra.ActionType, &allowed); err != nil {
			return nil, fmt.Errorf("permifysync: scan snapshot row: %w", err)
		}
		data[ra] = allowed
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("permifysync: iterate snapshot rows: %w", err)
	}
	return data, nil
}

var _ SnapshotStore = (*PgSnapshotStore)(nil)
