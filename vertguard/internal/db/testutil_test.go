package db

import (
	"context"
	"embed"
	"io/fs"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ---------------------------------------------------------------------------
// Integration test helpers — mirrors the pattern used by internal/db in
// sibling platforms (e.g. securelab, opencsirt): skip automatically when no
// live Postgres is configured, apply the embedded migrations exactly once
// per test binary run, and truncate between tests so cases stay isolated.
// ---------------------------------------------------------------------------

//go:embed migrations/*.sql
var testMigrationsFS embed.FS

// dbURL returns the DSN to use for integration tests. Tests that call this
// skip automatically when DATABASE_URL is unset, so this file is a no-op on
// machines without a live Postgres available.
func dbURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv("DATABASE_URL")
	if u == "" {
		t.Skip("DATABASE_URL not set — skipping db integration test")
	}
	return u
}

var (
	migrationsOnce sync.Once
	migrationsErr  error
)

// ensureSchema applies every embedded *.sql migration file against
// connString, once per test binary invocation. The migrations use
// CREATE TABLE/INDEX IF NOT EXISTS guards, so re-running is safe — this
// just avoids redundant round-trips on every test.
func ensureSchema(t *testing.T, connString string) {
	t.Helper()
	migrationsOnce.Do(func() {
		migrationsErr = applyMigrations(connString)
	})
	if migrationsErr != nil {
		t.Fatalf("applying migrations: %v", migrationsErr)
	}
}

func applyMigrations(connString string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return err
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		return err
	}

	entries, err := fs.ReadDir(testMigrationsFS, "migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		data, err := testMigrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		if _, err := pool.Exec(ctx, string(data)); err != nil {
			return err
		}
	}
	return nil
}

// openTestDB returns a ready *DB against the test database, with the
// schema applied and the pool closed automatically at test end.
func openTestDB(t *testing.T) *DB {
	t.Helper()
	url := dbURL(t)
	ensureSchema(t, url)

	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return &DB{Pool: pool}
}

// truncateTables clears the given tables so tests don't interfere with
// each other via lingering rows.
func truncateTables(t *testing.T, d *DB, tables ...string) {
	t.Helper()
	if len(tables) == 0 {
		return
	}
	sql := "TRUNCATE TABLE " + strings.Join(tables, ", ")
	if _, err := d.Pool.Exec(context.Background(), sql); err != nil {
		t.Fatalf("truncating tables %v: %v", tables, err)
	}
}
