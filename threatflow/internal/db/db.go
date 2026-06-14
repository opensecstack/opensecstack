// Package db provides PostgreSQL connection management, migrations, and
// typed CRUD stores for ThreatFlow.
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/threatflow/internal/config"
)

// DB wraps a pgx connection pool.
type DB struct {
	Pool *pgxpool.Pool
}

// Open creates a new pool from the given DatabaseConfig and verifies connectivity.
func Open(ctx context.Context, cfg config.DatabaseConfig) (*DB, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("parse db url: %w", err)
	}
	if cfg.MaxOpenConns > 0 {
		// #nosec G115 — config values are bounded by human-tuned YAML;
		// operators don't set pool sizes in the billions.
		poolCfg.MaxConns = int32(cfg.MaxOpenConns) //nolint:gosec
	}
	if cfg.MaxIdleConns > 0 {
		// #nosec G115 — same rationale as MaxConns.
		poolCfg.MinConns = int32(cfg.MaxIdleConns) //nolint:gosec
	}
	poolCfg.MaxConnLifetime = time.Hour
	poolCfg.MaxConnIdleTime = 30 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}

	return &DB{Pool: pool}, nil
}

// Close releases all pool connections.
func (d *DB) Close() {
	if d.Pool != nil {
		d.Pool.Close()
	}
}
