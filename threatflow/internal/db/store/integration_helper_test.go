//go:build integration

package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// testDB wires a single shared pool for all store integration tests. Every
// test is wrapped in t.Run(transactional) and resets the schema between
// runs so correlations / ioc upserts do not leak between cases.
//
// Requires THREATFLOW_TEST_DB_URL to point at a fresh database — the test
// helper runs every migration in internal/db/migrations from scratch.
// Skips when the env var is unset so `go test ./...` stays fast.
func testDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("THREATFLOW_TEST_DB_URL")
	if dsn == "" {
		t.Skip("THREATFLOW_TEST_DB_URL not set; skipping integration tests")
	}

	runMigrations(t, dsn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)

	truncate(t, pool)
	return pool
}

// runMigrations applies every migration from internal/db/migrations on the
// first call for a given process. Idempotent — golang-migrate reports
// ErrNoChange on subsequent runs.
func runMigrations(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql open: %v", err)
	}
	defer db.Close()

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		t.Fatalf("driver: %v", err)
	}
	mig, err := migrate.NewWithDatabaseInstance(
		"file://../migrations",
		"postgres", driver,
	)
	if err != nil {
		t.Fatalf("migrate init: %v", err)
	}
	if err := mig.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("migrate up: %v", err)
	}
}

// truncate wipes every mutable table. Kept as explicit TRUNCATE statements
// so a missing table in the migrations (which would silently skip) fails
// the test rather than producing confusing leaks.
func truncate(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx, `
TRUNCATE TABLE
  ioc_correlations,
  ttp_tags,
  sightings,
  advisory_remediations,
  advisory_vulnerabilities,
  advisory_products,
  advisory_revisions,
  advisories,
  stix_objects,
  stix_bundles,
  iocs,
  feeds,
  webhook_deliveries,
  webhook_subscribers,
  api_keys
RESTART IDENTITY CASCADE`)
	if err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

func mustOK(t *testing.T, err error, msg string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", msg, err)
	}
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }
