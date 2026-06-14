package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// StixBundle mirrors a row from stix_bundles.
type StixBundle struct {
	ID          uuid.UUID `json:"id"`
	StixID      string    `json:"stix_id"`
	Direction   string    `json:"direction"`
	Source      string    `json:"source"`
	ObjectCount int       `json:"object_count"`
	BundleHash  string    `json:"bundle_hash"`
	CreatedAt   time.Time `json:"created_at"`
}

// StixObject mirrors a row from stix_objects.
type StixObject struct {
	ID        uuid.UUID       `json:"id"`
	StixID    string          `json:"stix_id"`
	StixType  string          `json:"stix_type"`
	BundleID  uuid.UUID       `json:"bundle_id"`
	Content   []byte          `json:"-"`
	CreatedAt time.Time       `json:"created_at"`
}

// StixStore persists stix_bundles and stix_objects rows.
type StixStore struct {
	pool *pgxpool.Pool
}

// NewStixStore returns a store bound to the given pool.
func NewStixStore(pool *pgxpool.Pool) *StixStore {
	return &StixStore{pool: pool}
}

// HashBundle returns SHA-256 of the bundle payload, hex-encoded.
func HashBundle(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// CreateBundle inserts a bundle record. Duplicate stix_id returns the existing row.
func (s *StixStore) CreateBundle(ctx context.Context, b *StixBundle) error {
	const q = `
INSERT INTO stix_bundles (stix_id, direction, source, object_count, bundle_hash)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (stix_id) DO UPDATE SET object_count = EXCLUDED.object_count
RETURNING id, created_at`
	return s.pool.QueryRow(ctx, q,
		b.StixID, b.Direction, b.Source, b.ObjectCount, b.BundleHash,
	).Scan(&b.ID, &b.CreatedAt)
}

// InsertObject persists a single STIX object. Returns nil when the object
// already exists (idempotent imports).
func (s *StixStore) InsertObject(ctx context.Context, o *StixObject) error {
	const q = `
INSERT INTO stix_objects (stix_id, stix_type, bundle_id, content)
VALUES ($1, $2, $3, $4::jsonb)
ON CONFLICT (stix_id) DO NOTHING
RETURNING id, created_at`
	err := s.pool.QueryRow(ctx, q, o.StixID, o.StixType, o.BundleID, o.Content).
		Scan(&o.ID, &o.CreatedAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("insert stix object: %w", err)
	}
	return nil
}

// ListBundles returns bundles ordered by created_at DESC.
func (s *StixStore) ListBundles(ctx context.Context, direction string, limit, offset int) ([]*StixBundle, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	where := ""
	args := []any{}
	if direction != "" {
		where = " WHERE direction = $1"
		args = append(args, direction)
	}
	var total int
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM stix_bundles"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	args = append(args, limit, offset)
	limitArg := len(args) - 1
	offsetArg := len(args)
	listQ := fmt.Sprintf(`
SELECT id, stix_id, direction, source, object_count, bundle_hash, created_at
FROM stix_bundles%s
ORDER BY created_at DESC
LIMIT $%d OFFSET $%d`, where, limitArg, offsetArg)

	rows, err := s.pool.Query(ctx, listQ, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []*StixBundle
	for rows.Next() {
		var b StixBundle
		if err := rows.Scan(&b.ID, &b.StixID, &b.Direction, &b.Source, &b.ObjectCount, &b.BundleHash, &b.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, &b)
	}
	return out, total, rows.Err()
}

// GetBundle fetches a bundle by its internal UUID.
func (s *StixStore) GetBundle(ctx context.Context, id uuid.UUID) (*StixBundle, error) {
	const q = `
SELECT id, stix_id, direction, source, object_count, bundle_hash, created_at
FROM stix_bundles WHERE id = $1`
	var b StixBundle
	err := s.pool.QueryRow(ctx, q, id).Scan(
		&b.ID, &b.StixID, &b.Direction, &b.Source, &b.ObjectCount, &b.BundleHash, &b.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &b, err
}

// ObjectsForBundle returns all STIX objects in a bundle.
func (s *StixStore) ObjectsForBundle(ctx context.Context, bundleID uuid.UUID) ([]*StixObject, error) {
	const q = `
SELECT id, stix_id, stix_type, bundle_id, content::text, created_at
FROM stix_objects WHERE bundle_id = $1 ORDER BY stix_type, stix_id`
	rows, err := s.pool.Query(ctx, q, bundleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*StixObject
	for rows.Next() {
		var (
			o       StixObject
			content string
		)
		if err := rows.Scan(&o.ID, &o.StixID, &o.StixType, &o.BundleID, &content, &o.CreatedAt); err != nil {
			return nil, err
		}
		o.Content = []byte(content)
		out = append(out, &o)
	}
	return out, rows.Err()
}
