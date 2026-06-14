package db

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/jackc/pgx/v5/stdlib"
	"database/sql"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Migrator wraps golang-migrate with ThreatFlow-specific defaults.
type Migrator struct {
	m *migrate.Migrate
}

// NewMigrator builds a Migrator for the given DSN using embedded migration files.
func NewMigrator(dsn string) (*Migrator, error) {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("sub fs: %w", err)
	}
	src, err := iofs.New(sub, ".")
	if err != nil {
		return nil, fmt.Errorf("iofs: %w", err)
	}

	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	driver, err := postgres.WithInstance(sqlDB, &postgres.Config{})
	if err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("driver: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", src, "postgres", driver)
	if err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Migrator{m: m}, nil
}

// Up applies all pending migrations. Returns nil if already up-to-date.
func (mg *Migrator) Up() error {
	if err := mg.m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}

// Down rolls back N migrations. If n <= 0, rolls back all.
func (mg *Migrator) Down(n int) error {
	if n <= 0 {
		return mg.m.Down()
	}
	return mg.m.Steps(-n)
}

// Target migrates to a specific version.
func (mg *Migrator) Target(version uint) error {
	return mg.m.Migrate(version)
}

// Force sets the schema version without running migrations. Use for recovery only.
func (mg *Migrator) Force(version int) error {
	return mg.m.Force(version)
}

// Status returns the current version and whether the schema is marked dirty.
func (mg *Migrator) Status() (version uint, dirty bool, err error) {
	v, d, e := mg.m.Version()
	if errors.Is(e, migrate.ErrNilVersion) {
		return 0, false, nil
	}
	return v, d, e
}

// Close releases the underlying migrator resources.
func (mg *Migrator) Close() error {
	srcErr, dbErr := mg.m.Close()
	if srcErr != nil {
		return srcErr
	}
	return dbErr
}
