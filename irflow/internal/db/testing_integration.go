//go:build integration

// Package db integration test helpers. Compiled only under the
// `integration` build tag so go test ./... keeps running in seconds for the
// default local developer workflow.
package db

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// testPool is shared across every integration test in a single run so we
// only pay for TCP + TLS setup once.
var (
	testPoolOnce sync.Once
	testPool     *pgxpool.Pool
	testPoolErr  error
	migrateOnce  sync.Once
	migrateErr   error
)

// openTestPool returns a pgxpool shared across all integration tests in the
// current process. It reads IRFLOW_TEST_DB_URL; if unset, the test is skipped.
func openTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("IRFLOW_TEST_DB_URL")
	if dsn == "" {
		t.Skip("IRFLOW_TEST_DB_URL not set — skipping integration test. Use `make test-integration` or `docker compose -f docker-compose.test.yml up -d` first.")
	}
	testPoolOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		testPool, testPoolErr = pgxpool.New(ctx, dsn)
	})
	if testPoolErr != nil {
		t.Fatalf("connect test db: %v", testPoolErr)
	}
	return testPool
}

// applyMigrationsOnce runs every migrations/*.sql file in order. Safe to call
// from any test — the work is done exactly once per process lifetime. Later
// tests start with a clean slate via truncateAll.
func applyMigrationsOnce(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	migrateOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()

		if _, err := pool.Exec(ctx, `
			CREATE TABLE IF NOT EXISTS schema_migrations (
				version VARCHAR(50) PRIMARY KEY,
				applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
			)`); err != nil {
			migrateErr = err
			return
		}

		migrationsDir, err := findMigrationsDir()
		if err != nil {
			migrateErr = err
			return
		}
		entries, err := os.ReadDir(migrationsDir)
		if err != nil {
			migrateErr = err
			return
		}
		var files []string
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
				continue
			}
			files = append(files, filepath.Join(migrationsDir, e.Name()))
		}
		sort.Strings(files)

		for _, f := range files {
			name := filepath.Base(f)
			// Skip if already applied in a previous process run. Tests expect
			// schema to exist, so we don't drop/recreate between processes.
			var exists bool
			if err := pool.QueryRow(ctx,
				"SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)", name,
			).Scan(&exists); err != nil {
				migrateErr = err
				return
			}
			if exists {
				continue
			}
			sqlBytes, err := os.ReadFile(f)
			if err != nil {
				migrateErr = err
				return
			}
			if _, err := pool.Exec(ctx, string(sqlBytes)); err != nil {
				migrateErr = err
				return
			}
			if _, err := pool.Exec(ctx,
				"INSERT INTO schema_migrations(version) VALUES ($1) ON CONFLICT DO NOTHING", name,
			); err != nil {
				migrateErr = err
				return
			}
		}
	})
	if migrateErr != nil {
		t.Fatalf("apply migrations: %v", migrateErr)
	}
}

// truncateAll wipes every domain table. Called by t.Cleanup in each
// integration test so tests remain independent without tearing down schema.
func truncateAll(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := pool.Exec(ctx, `
		TRUNCATE
			timeline_entries,
			ioc_enrichments,
			incident_actions,
			playbook_executions,
			incidents,
			playbooks
		RESTART IDENTITY CASCADE`)
	if err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

// setupDB is the canonical per-test fixture: apply migrations (once per
// process), truncate all tables, return the pool. Tests typically call:
//
//	pool := setupDB(t)
//	// ... use PGStore(pool) ...
func setupDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := openTestPool(t)
	applyMigrationsOnce(t, pool)
	truncateAll(t, pool)
	t.Cleanup(func() { truncateAll(t, pool) })
	return pool
}

// findMigrationsDir walks up from the current file until it finds a
// "migrations" directory. This makes tests work regardless of where the
// `go test` command is invoked from.
func findMigrationsDir() (string, error) {
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Dir(thisFile)
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, "migrations")
		if st, err := os.Stat(candidate); err == nil && st.IsDir() {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", os.ErrNotExist
}
