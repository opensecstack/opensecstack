package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// IOCIngestLog is one row of the ioc_ingest_log table.
type IOCIngestLog struct {
	ID           uuid.UUID
	Source       string
	BundleSHA256 string
	Count        int
	IngestedAt   time.Time
}

// IOCIngestLogStore writes audit rows for each IOC pull.
type IOCIngestLogStore struct {
	pool *pgxpool.Pool
}

// NewIOCIngestLogStore wraps a pool.
func NewIOCIngestLogStore(pool *pgxpool.Pool) *IOCIngestLogStore {
	return &IOCIngestLogStore{pool: pool}
}

// ErrIOCBundleAlreadyIngested is returned by Insert when the
// (source, bundle_sha256) UNIQUE constraint fires — the worker uses it
// to skip already-applied bundles cheaply.
var ErrIOCBundleAlreadyIngested = errors.New("ioc bundle already ingested")

// Insert logs one ingest. Returns ErrIOCBundleAlreadyIngested if a row
// with the same (source, bundle_sha256) already exists.
func (s *IOCIngestLogStore) Insert(ctx context.Context, source, sha string, count int) (IOCIngestLog, error) {
	const q = `INSERT INTO ioc_ingest_log (source, bundle_sha256, count)
	           VALUES ($1, $2, $3)
	           RETURNING id, ingested_at`
	var (
		id        uuid.UUID
		ingestedAt time.Time
	)
	err := s.pool.QueryRow(ctx, q, source, sha, count).Scan(&id, &ingestedAt)
	if err != nil {
		// 23505 = unique_violation.
		var pgErr interface{ SQLState() string }
		if errors.As(err, &pgErr) && pgErr.SQLState() == "23505" {
			return IOCIngestLog{}, ErrIOCBundleAlreadyIngested
		}
		return IOCIngestLog{}, fmt.Errorf("insert ioc log: %w", err)
	}
	return IOCIngestLog{
		ID: id, Source: source, BundleSHA256: sha,
		Count: count, IngestedAt: ingestedAt,
	}, nil
}

// LastForSource returns the most recent ingest row for a source. Used
// by the worker to expose "last successful pull" on /api/v1/health.
func (s *IOCIngestLogStore) LastForSource(ctx context.Context, source string) (IOCIngestLog, error) {
	const q = `SELECT id, source, bundle_sha256, count, ingested_at
	           FROM ioc_ingest_log
	           WHERE source = $1
	           ORDER BY ingested_at DESC LIMIT 1`
	var l IOCIngestLog
	err := s.pool.QueryRow(ctx, q, source).Scan(&l.ID, &l.Source, &l.BundleSHA256, &l.Count, &l.IngestedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return IOCIngestLog{}, nil
	}
	return l, err
}
