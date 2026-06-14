package ioc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned by GetByValue when no row matches.
var ErrNotFound = errors.New("ioc: not found")

// Store is a pgx-backed CRUD over the iocs + ioc_pull_audit tables.
// Concurrency-safe: pgxpool serialises all access internally.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore wraps an existing pool. Returns nil when pool is nil so the
// caller can keep the store optional.
func NewStore(pool *pgxpool.Pool) *Store {
	if pool == nil {
		return nil
	}
	return &Store{pool: pool}
}

// UpsertResult lets the puller distinguish first-time inserts from
// refresh-only updates so the per-source audit row carries useful
// counters.
type UpsertResult int

const (
	UpsertInserted UpsertResult = iota
	UpsertUpdated
)

// Upsert writes one IOC. On (kind, value, tenant) conflict it bumps
// last_seen + confidence + source (latest wins) and refreshes
// expires_at + tags. The returned result tells the caller whether a
// new row was created.
func (s *Store) Upsert(ctx context.Context, in IOC) (UpsertResult, error) {
	if in.ID == uuid.Nil {
		in.ID = uuid.New()
	}
	now := time.Now().UTC()
	if in.FirstSeen.IsZero() {
		in.FirstSeen = now
	}
	if in.LastSeen.IsZero() {
		in.LastSeen = now
	}
	if in.Tags == nil {
		in.Tags = []string{}
	}
	var expires any
	if in.ExpiresAt != nil {
		expires = in.ExpiresAt.UTC()
	}
	// xmax=0 is the canonical pgx idiom for "INSERT path"; when the
	// ON CONFLICT branch fires xmax is non-zero. Avoids a second query
	// to detect insert-vs-update.
	var inserted bool
	err := s.pool.QueryRow(ctx, `
		INSERT INTO iocs (
			id, kind, value, source, confidence, tags,
			first_seen, last_seen, expires_at, tenant, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now(),now())
		ON CONFLICT (kind, value, tenant) DO UPDATE SET
			source     = EXCLUDED.source,
			confidence = GREATEST(iocs.confidence, EXCLUDED.confidence),
			tags       = EXCLUDED.tags,
			last_seen  = EXCLUDED.last_seen,
			expires_at = EXCLUDED.expires_at,
			updated_at = now()
		RETURNING (xmax = 0)`,
		in.ID, string(in.Kind), in.Value, in.Source, in.Confidence, in.Tags,
		in.FirstSeen.UTC(), in.LastSeen.UTC(), expires, in.Tenant,
	).Scan(&inserted)
	if err != nil {
		return 0, fmt.Errorf("upsert ioc: %w", err)
	}
	if inserted {
		return UpsertInserted, nil
	}
	return UpsertUpdated, nil
}

// ListFilter narrows a List call. Cursor is an opaque numeric offset
// (matching the existing handler contract). Limit is clamped by the
// caller.
type ListFilter struct {
	Kind   string
	Source string
	Tenant string
	Cursor int
	Limit  int
}

// List returns one page of IOCs ordered by (last_seen DESC, id) plus
// the next cursor (offset+len) when more rows are likely available.
func (s *Store) List(ctx context.Context, f ListFilter) ([]IOC, int, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	if f.Cursor < 0 {
		f.Cursor = 0
	}
	q := `SELECT id, kind, value, source, confidence, tags,
	             first_seen, last_seen, expires_at, tenant, created_at, updated_at
	      FROM iocs WHERE 1=1`
	args := []any{}
	if f.Kind != "" {
		args = append(args, f.Kind)
		q += fmt.Sprintf(" AND kind=$%d", len(args))
	}
	if f.Source != "" {
		args = append(args, f.Source)
		q += fmt.Sprintf(" AND source=$%d", len(args))
	}
	if f.Tenant != "" {
		args = append(args, f.Tenant)
		q += fmt.Sprintf(" AND tenant=$%d", len(args))
	}
	args = append(args, f.Limit)
	args = append(args, f.Cursor)
	q += fmt.Sprintf(" ORDER BY last_seen DESC, id LIMIT $%d OFFSET $%d",
		len(args)-1, len(args))

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list iocs: %w", err)
	}
	defer rows.Close()

	out := make([]IOC, 0, f.Limit)
	for rows.Next() {
		var (
			r         IOC
			kind      string
			expiresAt *time.Time
		)
		if err := rows.Scan(&r.ID, &kind, &r.Value, &r.Source, &r.Confidence,
			&r.Tags, &r.FirstSeen, &r.LastSeen, &expiresAt, &r.Tenant,
			&r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, 0, fmt.Errorf("scan ioc: %w", err)
		}
		r.Kind = Kind(kind)
		r.ExpiresAt = expiresAt
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	next := 0
	if len(out) == f.Limit {
		next = f.Cursor + f.Limit
	}
	return out, next, nil
}

// GetByValue returns a single IOC by (kind, value, tenant) — the
// natural unique key. Returns ErrNotFound when no row matches.
func (s *Store) GetByValue(ctx context.Context, kind Kind, value, tenant string) (*IOC, error) {
	var (
		r         IOC
		k         string
		expiresAt *time.Time
	)
	err := s.pool.QueryRow(ctx, `
		SELECT id, kind, value, source, confidence, tags,
		       first_seen, last_seen, expires_at, tenant, created_at, updated_at
		FROM iocs WHERE kind=$1 AND value=$2 AND tenant=$3`,
		string(kind), value, tenant,
	).Scan(&r.ID, &k, &r.Value, &r.Source, &r.Confidence, &r.Tags,
		&r.FirstSeen, &r.LastSeen, &expiresAt, &r.Tenant,
		&r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get ioc: %w", err)
	}
	r.Kind = Kind(k)
	r.ExpiresAt = expiresAt
	return &r, nil
}

// ExpireSweep deletes rows whose expires_at is non-null and in the past.
// Returns the deletion count for the caller's metrics.
func (s *Store) ExpireSweep(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM iocs WHERE expires_at IS NOT NULL AND expires_at < now()`)
	if err != nil {
		return 0, fmt.Errorf("expire sweep: %w", err)
	}
	return tag.RowsAffected(), nil
}

// CountActive returns the number of non-expired rows. Used to feed
// vertguard_ioc_active_total after each sweep.
func (s *Store) CountActive(ctx context.Context) (int64, error) {
	var n int64
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM iocs WHERE expires_at IS NULL OR expires_at > now()`,
	).Scan(&n); err != nil {
		return 0, fmt.Errorf("count active iocs: %w", err)
	}
	return n, nil
}

// AuditInsert writes one ioc_pull_audit row. Always called once per
// Tick so operators can grep the table for failed/empty pulls.
func (s *Store) AuditInsert(ctx context.Context, a PullAudit) error {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	var errStr any
	if a.Error != "" {
		errStr = a.Error
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO ioc_pull_audit (
			id, source, started_at, finished_at,
			fetched, inserted, updated, skipped, error
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		a.ID, a.Source, a.StartedAt.UTC(), a.FinishedAt.UTC(),
		a.Fetched, a.Inserted, a.Updated, a.Skipped, errStr,
	)
	if err != nil {
		return fmt.Errorf("insert ioc audit: %w", err)
	}
	return nil
}
