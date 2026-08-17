package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"

	"github.com/opensecstack/sinauth/internal/config"
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Run database migrations",
	RunE:  runMigrate,
}

func init() {
	migrateCmd.Flags().String("dir", "migrations", "Directory containing .sql migration files")
}

func runMigrate(cmd *cobra.Command, _ []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	dir, _ := cmd.Flags().GetString("dir")

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.DBURL)
	if err != nil {
		return fmt.Errorf("db connect: %w", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("db ping: %w", err)
	}

	// Ensure migrations tracking table exists.
	_, err = pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			filename TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`)
	if err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	// Read applied migrations.
	rows, err := pool.Query(ctx, `SELECT filename FROM schema_migrations ORDER BY filename`)
	if err != nil {
		return fmt.Errorf("query applied migrations: %w", err)
	}
	applied := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		applied[name] = true
	}
	rows.Close()

	// Find .sql files.
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read migrations dir %q: %w", dir, err)
	}
	files := sqlFileNames(entries)
	pending := pendingFiles(files, applied)

	// Apply pending migrations.
	count := 0
	for _, name := range pending {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}

		if err := applyMigration(ctx, pool, name, string(data)); err != nil {
			return fmt.Errorf("apply %s: %w", name, err)
		}

		log.Printf("sinauth: applied %s", name)
		count++
	}

	if count == 0 {
		log.Println("sinauth: no pending migrations")
	} else {
		log.Printf("sinauth: applied %d migration(s)", count)
	}
	return nil
}

func applyMigration(ctx context.Context, pool *pgxpool.Pool, name, sql string) error {
	return pgx.BeginTxFunc(ctx, pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, sql); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO schema_migrations (filename) VALUES ($1)`, name)
		return err
	})
}

// sqlFileNames extracts the sorted list of *.sql filenames (directories and
// non-.sql entries excluded) from a directory listing. Split out of
// runMigrate so the file-selection logic is unit-testable against a fake
// os.DirEntry slice, without needing a real migrations directory on disk.
func sqlFileNames(entries []os.DirEntry) []string {
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	return files
}

// pendingFiles filters files down to the ones not present in applied,
// preserving order. Split out of runMigrate so the pending-vs-applied
// decision is unit-testable independent of the DB query that produces
// applied and the filesystem walk that produces files.
func pendingFiles(files []string, applied map[string]bool) []string {
	var pending []string
	for _, f := range files {
		if !applied[f] {
			pending = append(pending, f)
		}
	}
	return pending
}
