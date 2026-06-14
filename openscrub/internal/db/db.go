// Package db is the Postgres persistence layer for OpenScrub.
//
// One DB struct (pgxpool wrapper) and three stores: RuleStore,
// IOCIngestLogStore, MitigationStore. Each is independently
// constructible and unit-testable against a real Postgres (the
// integration tests skip if OPENSCRUB_TEST_DB_URL is unset, mirroring
// the cyberpath pattern).
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DB wraps a pgxpool for use by the stores.
type DB struct {
	Pool *pgxpool.Pool
}

// New opens a pool and pings it.
func New(ctx context.Context, url string, maxConns int32) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse db url: %w", err)
	}
	if maxConns > 0 {
		cfg.MaxConns = maxConns
	}
	cfg.MaxConnLifetime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("initial ping: %w", err)
	}
	return &DB{Pool: pool}, nil
}

// Ping satisfies the health-check interface used by /api/v1/health.
func (d *DB) Ping(ctx context.Context) error {
	if d == nil || d.Pool == nil {
		return fmt.Errorf("db not initialised")
	}
	return d.Pool.Ping(ctx)
}

// Close releases the pool.
func (d *DB) Close() {
	if d != nil && d.Pool != nil {
		d.Pool.Close()
	}
}
