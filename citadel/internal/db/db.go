package db

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DB wraps a pgx connection pool.
type DB struct {
	Pool *pgxpool.Pool

	// anchorKey is the Ed25519 master key used to sign (and verify) WORM
	// anchors. nil means anchoring is disabled — see ConfigureAnchoring in
	// worm.go. Never logged or exposed outside this package.
	anchorKey ed25519.PrivateKey
	// anchorInterval is how many WORM entries between anchor signatures.
	// 0 means anchoring has not been configured at all (distinct from "no
	// master key" — see ConfigureAnchoring).
	anchorInterval int
}

// New creates a new DB instance with a pgx connection pool.
func New(ctx context.Context, connString string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("parsing connection string: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("creating connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging database: %w", err)
	}

	return &DB{Pool: pool}, nil
}

// Close shuts down the connection pool.
func (d *DB) Close() {
	d.Pool.Close()
}

// Ping verifies the database connection is alive.
func (d *DB) Ping(ctx context.Context) error {
	return d.Pool.Ping(ctx)
}
