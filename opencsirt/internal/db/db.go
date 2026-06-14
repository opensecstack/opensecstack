// Package db wraps the pgx connection pool and exposes typed stores.
package db

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is the canonical "no such row" sentinel.
var ErrNotFound = errors.New("db: not found")

// ErrConflict is returned when a state-transition is invalid (e.g. withdraw a non-published advisory).
var ErrConflict = errors.New("db: conflict")

type Pool = pgxpool.Pool

// Open creates a pgx pool from a DSN, sized to maxConns.
func Open(ctx context.Context, dsn string, maxConns int) (*Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	if maxConns > 0 {
		cfg.MaxConns = int32(maxConns)
	}
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.HealthCheckPeriod = 1 * time.Minute
	return pgxpool.NewWithConfig(ctx, cfg)
}
