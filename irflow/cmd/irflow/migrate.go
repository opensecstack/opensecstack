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
	"github.com/spf13/cobra"

	"github.com/opensecstack/opensecstack/irflow/internal/config"
	"github.com/opensecstack/opensecstack/irflow/internal/db"
)

var migrationsDir string

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Apply pending SQL migrations from the migrations directory",
	RunE:  runMigrate,
}

func init() {
	migrateCmd.Flags().StringVar(&migrationsDir, "dir", "migrations",
		"directory containing .sql migration files (sorted lexicographically)")
}

func runMigrate(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	pool, err := db.NewPool(ctx,
		cfg.DB.Host, cfg.DB.Port, cfg.DB.Name,
		cfg.DB.User, cfg.DB.Password, cfg.DB.SSLMode,
	)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer pool.Close()

	if err := ensureMigrationsTable(ctx, pool); err != nil {
		return fmt.Errorf("ensuring schema_migrations table: %w", err)
	}

	applied, err := appliedMigrations(ctx, pool)
	if err != nil {
		return fmt.Errorf("reading applied migrations: %w", err)
	}

	files, err := listMigrationFiles(migrationsDir)
	if err != nil {
		return fmt.Errorf("listing migration files in %s: %w", migrationsDir, err)
	}

	if len(files) == 0 {
		fmt.Printf("migrate: no .sql files found in %s\n", migrationsDir)
		return nil
	}

	pending := 0
	for _, file := range files {
		name := filepath.Base(file)
		if applied[name] {
			continue
		}
		if err := applyMigration(ctx, pool, file, name); err != nil {
			return fmt.Errorf("applying %s: %w", name, err)
		}
		fmt.Printf("migrate: applied %s\n", name)
		pending++
	}

	if pending == 0 {
		fmt.Println("migrate: database is up to date")
	} else {
		fmt.Printf("migrate: applied %d migration(s)\n", pending)
	}
	return nil
}

func ensureMigrationsTable(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version VARCHAR(50) PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`)
	return err
}

func appliedMigrations(ctx context.Context, pool *pgxpool.Pool) (map[string]bool, error) {
	rows, err := pool.Query(ctx, "SELECT version FROM schema_migrations")
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

func listMigrationFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		files = append(files, filepath.Join(dir, e.Name()))
	}
	sort.Strings(files)
	return files, nil
}

func applyMigration(ctx context.Context, pool *pgxpool.Pool, path, name string) error {
	sqlBytes, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, string(sqlBytes)); err != nil {
		return fmt.Errorf("executing sql: %w", err)
	}

	if _, err := tx.Exec(ctx,
		"INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT DO NOTHING",
		name,
	); err != nil {
		return fmt.Errorf("recording migration: %w", err)
	}

	return tx.Commit(ctx)
}
