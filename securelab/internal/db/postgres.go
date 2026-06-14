// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/opensecstack/securelab/internal/config"
)

// New opens a pgxpool connection pool using the supplied configuration,
// verifies the connection with a Ping, and returns the ready pool.
// The caller is responsible for calling pool.Close() on shutdown.
func New(ctx context.Context, cfg *config.Config) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DBUrl)
	if err != nil {
		return nil, fmt.Errorf("db: parse config: %w", err)
	}

	poolCfg.MaxConns = int32(cfg.DBMaxConns)

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("db: open pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}

	return pool, nil
}
