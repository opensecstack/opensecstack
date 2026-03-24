package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DB wraps a pgx connection pool and provides data access methods.
type DB struct {
	Pool *pgxpool.Pool
}

// New creates a new DB instance with a pgx connection pool.
func New(ctx context.Context, connString string) (*DB, error) {
	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("parsing connection string: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, config)
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
