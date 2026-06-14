// Package db provides the PostgreSQL connection pool + query helpers.
//
// STATUS: Phase 4.1 initial. Satisfies handlers.Pinger via Ping().
// Query helpers for prompt_scans + threat_iocs added alongside the
// respective handlers.
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DB wraps a pgx connection pool plus metadata.
type DB struct {
	Pool *pgxpool.Pool
}

// New opens a pgxpool and ensures the connection is healthy.
//
// minConns is the explicit floor: when > 0 it is applied verbatim. When
// 0 and maxConns is set, a sensible derived floor (max(5, maxConns/5))
// is applied so the pool doesn't shrink to zero under idle and pay
// reconnect latency on the next request burst.
func New(ctx context.Context, url string, maxConns int32, minConns int32) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse db url: %w", err)
	}
	if maxConns > 0 {
		cfg.MaxConns = maxConns
		floor := minConns
		if floor <= 0 {
			floor = maxConns / 5
			if floor < 5 {
				floor = 5
			}
		}
		// Clamp to MaxConns so an over-sized override doesn't trip
		// pgxpool's own validation.
		if floor > maxConns {
			floor = maxConns
		}
		cfg.MinConns = floor
	} else if minConns > 0 {
		cfg.MinConns = minConns
	}
	cfg.MaxConnLifetime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	ctxPing, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(ctxPing); err != nil {
		pool.Close()
		return nil, fmt.Errorf("initial ping: %w", err)
	}

	return &DB{Pool: pool}, nil
}

// Ping satisfies handlers.Pinger — used by /health.
func (d *DB) Ping(ctx context.Context) error {
	return d.Pool.Ping(ctx)
}

// Close releases the pool.
func (d *DB) Close() {
	if d != nil && d.Pool != nil {
		d.Pool.Close()
	}
}
