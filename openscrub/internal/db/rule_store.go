package db

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/openscrub/internal/rules"
)

// ErrRuleNotFound is returned by Get/Delete when no row matches. It
// wraps rules.ErrNotFound so the service layer can use errors.Is
// without falling back to string comparison.
var ErrRuleNotFound = fmt.Errorf("db: %w", rules.ErrNotFound)

// RuleStore persists rules.Rule rows.
type RuleStore struct {
	pool *pgxpool.Pool
}

// NewRuleStore wraps a pool.
func NewRuleStore(pool *pgxpool.Pool) *RuleStore {
	return &RuleStore{pool: pool}
}

// Insert writes a new rule. The CIDR (when present) is normalised
// before INSERT — '198.51.100.5/24' stored as '198.51.100.0/24'.
func (s *RuleStore) Insert(ctx context.Context, r rules.Rule) (rules.Rule, error) {
	var cidrArg any
	if r.CIDR != "" {
		prefix, err := rules.ParseCIDR(r.CIDR)
		if err != nil {
			return rules.Rule{}, fmt.Errorf("invalid cidr: %w", err)
		}
		r.CIDR = prefix.String()
		cidrArg = prefix
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

	const q = `INSERT INTO rules (id, type, cidr, pps, port, ttl_seconds, source, created_at, expires_at, created_by)
	           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	_, err := s.pool.Exec(ctx, q,
		r.ID, string(r.Type), cidrArg, r.PPS, r.Port, r.TTLSeconds,
		r.Source, r.CreatedAt, r.ExpiresAt, r.CreatedBy)
	if err != nil {
		return rules.Rule{}, fmt.Errorf("insert rule: %w", err)
	}
	return r, nil
}

// Get returns the rule for the given id.
func (s *RuleStore) Get(ctx context.Context, id uuid.UUID) (rules.Rule, error) {
	const q = `SELECT id, type, cidr, pps, port, ttl_seconds, source, created_at, expires_at, created_by
	           FROM rules WHERE id = $1`
	row := s.pool.QueryRow(ctx, q, id)
	r, err := scanRule(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return rules.Rule{}, ErrRuleNotFound
	}
	return r, err
}

// Delete removes the rule by id; returns ErrRuleNotFound if missing.
func (s *RuleStore) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM rules WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete rule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrRuleNotFound
	}
	return nil
}

// List returns up to `limit` rules starting at `offset`, ordered by
// (created_at DESC, id DESC). The `id DESC` tiebreaker guarantees a
// stable total order across pages — without it, rows that share a
// created_at (common when the IOC puller bulk-inserts a feed) shuffle
// between pages and a paginating client both misses and double-counts
// rows. When `kind` is non-empty it filters by type.
func (s *RuleStore) List(ctx context.Context, kind rules.Type, limit, offset int) ([]rules.Rule, error) {
	// Default page size when caller passes 0; hard cap raised so the
	// IOC puller can dedup against the full active set (the previous
	// 200-row default silently capped the dedup window and let the
	// puller re-insert duplicates once the live set exceeded 200).
	if limit <= 0 {
		limit = 200
	}
	if limit > 100_000 {
		limit = 100_000
	}
	if offset < 0 {
		offset = 0
	}
	var (
		args []any
		q    string
	)
	if kind != "" {
		q = `SELECT id, type, cidr, pps, port, ttl_seconds, source, created_at, expires_at, created_by
		     FROM rules WHERE type = $1 ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3`
		args = []any{string(kind), limit, offset}
	} else {
		q = `SELECT id, type, cidr, pps, port, ttl_seconds, source, created_at, expires_at, created_by
		     FROM rules ORDER BY created_at DESC, id DESC LIMIT $1 OFFSET $2`
		args = []any{limit, offset}
	}
	rowsRes, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list rules: %w", err)
	}
	defer rowsRes.Close()
	var out []rules.Rule
	for rowsRes.Next() {
		r, err := scanRule(rowsRes)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rowsRes.Err()
}

// DeleteExpired removes rules whose expires_at <= now and returns them
// so the service layer can withdraw them from the data plane and emit
// rule_change events.
func (s *RuleStore) DeleteExpired(ctx context.Context, now time.Time) ([]rules.Rule, error) {
	const q = `DELETE FROM rules WHERE expires_at <= $1
	           RETURNING id, type, cidr, pps, port, ttl_seconds, source, created_at, expires_at, created_by`
	rowsRes, err := s.pool.Query(ctx, q, now)
	if err != nil {
		return nil, fmt.Errorf("delete expired: %w", err)
	}
	defer rowsRes.Close()
	var out []rules.Rule
	for rowsRes.Next() {
		r, err := scanRule(rowsRes)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rowsRes.Err()
}

// Count returns the total number of currently-stored rules.
func (s *RuleStore) Count(ctx context.Context) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM rules`).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// CountByType returns active blocklist / ratelimit / syncookie counts in
// a single round-trip. Used by the snapshot endpoint instead of
// walking the whole rule list every 5 s.
func (s *RuleStore) CountByType(ctx context.Context) (blocklist, ratelimit, syncookie int, err error) {
	const q = `SELECT type, COUNT(*) FROM rules GROUP BY type`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return 0, 0, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var t string
		var n int
		if err := rows.Scan(&t, &n); err != nil {
			return 0, 0, 0, err
		}
		switch rules.Type(t) {
		case rules.TypeBlocklist:
			blocklist = n
		case rules.TypeRatelimit:
			ratelimit = n
		case rules.TypeSynCookie:
			syncookie = n
		}
	}
	return blocklist, ratelimit, syncookie, rows.Err()
}

// CountBlocklistByFamily returns the IPv4 / IPv6 split of blocklist
// rules in a single round-trip. Postgres' inet/cidr family() function
// drives the GROUP BY so we don't pull every prefix into Go just to
// classify it.
func (s *RuleStore) CountBlocklistByFamily(ctx context.Context) (v4, v6 int, err error) {
	const q = `SELECT family(cidr), COUNT(*)
	             FROM rules
	            WHERE type = 'blocklist' AND cidr IS NOT NULL
	         GROUP BY family(cidr)`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var fam, n int
		if err := rows.Scan(&fam, &n); err != nil {
			return 0, 0, err
		}
		switch fam {
		case 4:
			v4 = n
		case 6:
			v6 = n
		}
	}
	return v4, v6, rows.Err()
}

// scanRule decodes one row using either pgx.Row or pgx.Rows. The cidr
// column is nullable (syncookie rules carry a port instead).
func scanRule(r pgx.Row) (rules.Rule, error) {
	var (
		out       rules.Rule
		kind      string
		prefix    *netip.Prefix
		pps       *int
		port      *int
		createdBy *uuid.UUID
	)
	if err := r.Scan(&out.ID, &kind, &prefix, &pps, &port, &out.TTLSeconds,
		&out.Source, &out.CreatedAt, &out.ExpiresAt, &createdBy); err != nil {
		return rules.Rule{}, err
	}
	out.Type = rules.Type(kind)
	if prefix != nil {
		out.CIDR = prefix.String()
	}
	out.PPS = pps
	out.Port = port
	out.CreatedBy = createdBy
	return out, nil
}
