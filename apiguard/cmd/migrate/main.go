// Package main is the APIGuard database migration runner.
// Usage:
//
//	go run ./cmd/migrate up    — apply all pending migrations
//	go run ./cmd/migrate down  — roll back the last applied migration
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const migrationsDir = "migrations"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: migrate <up|down>")
		os.Exit(2)
	}
	direction := os.Args[1]

	dbURL := os.Getenv("APIGUARD_DB_URL")
	if dbURL == "" {
		dbURL = os.Getenv("DATABASE_URL")
	}
	if dbURL == "" {
		fatal("APIGUARD_DB_URL environment variable is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		fatal("connecting to database: %v", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		fatal("pinging database: %v", err)
	}

	if err := ensureMigrationsTable(ctx, pool); err != nil {
		fatal("creating schema_migrations table: %v", err)
	}

	switch direction {
	case "up":
		if err := migrateUp(ctx, pool); err != nil {
			fatal("running migrations: %v", err)
		}
	case "down":
		if err := migrateDown(ctx, pool); err != nil {
			fatal("rolling back migration: %v", err)
		}
	default:
		fatal("unknown direction %q — use 'up' or 'down'", direction)
	}
}

func ensureMigrationsTable(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version     TEXT PRIMARY KEY,
			applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	return err
}

func migrateUp(ctx context.Context, pool *pgxpool.Pool) error {
	files, err := listMigrationFiles("up")
	if err != nil {
		return err
	}

	applied, err := appliedVersions(ctx, pool)
	if err != nil {
		return err
	}

	pending := 0
	for _, f := range files {
		ver := migrationVersion(f)
		if applied[ver] {
			continue
		}

		sql, err := os.ReadFile(filepath.Join(migrationsDir, f))
		if err != nil {
			return fmt.Errorf("reading %s: %w", f, err)
		}

		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("starting transaction for %s: %w", f, err)
		}

		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("applying %s: %w", f, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, ver); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("recording %s: %w", f, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("committing %s: %w", f, err)
		}

		fmt.Printf("applied %s\n", f)
		pending++
	}

	if pending == 0 {
		fmt.Println("no pending migrations")
	} else {
		fmt.Printf("%d migration(s) applied\n", pending)
	}
	return nil
}

func migrateDown(ctx context.Context, pool *pgxpool.Pool) error {
	applied, err := appliedVersionsSorted(ctx, pool)
	if err != nil {
		return err
	}
	if len(applied) == 0 {
		fmt.Println("no migrations to roll back")
		return nil
	}

	last := applied[len(applied)-1]
	downFile := fmt.Sprintf("%s.down.sql", last)
	path := filepath.Join(migrationsDir, downFile)

	sql, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, string(sql)); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("applying %s: %w", downFile, err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM schema_migrations WHERE version = $1`, last); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}

	fmt.Printf("rolled back %s\n", downFile)
	return nil
}

func listMigrationFiles(direction string) ([]string, error) {
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		return nil, fmt.Errorf("reading %s/: %w", migrationsDir, err)
	}

	suffix := fmt.Sprintf(".%s.sql", direction)
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), suffix) {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	return files, nil
}

// migrationVersion extracts the numeric prefix from a filename like "001_create_scans.up.sql".
func migrationVersion(filename string) string {
	base := strings.TrimSuffix(strings.TrimSuffix(filename, ".sql"), ".up")
	base = strings.TrimSuffix(base, ".down")
	return base
}

func appliedVersions(ctx context.Context, pool *pgxpool.Pool) (map[string]bool, error) {
	rows, err := pool.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	applied := make(map[string]bool)
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		applied[v] = true
	}
	return applied, rows.Err()
}

func appliedVersionsSorted(ctx context.Context, pool *pgxpool.Pool) ([]string, error) {
	rows, err := pool.Query(ctx, `SELECT version FROM schema_migrations ORDER BY applied_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var versions []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		versions = append(versions, v)
	}
	return versions, rows.Err()
}

func fatal(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "migrate: "+msg+"\n", args...)
	os.Exit(1)
}
