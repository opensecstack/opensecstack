package db_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/opensecstack/community/internal/db"
)

func TestConnect_InvalidURL_ReturnsError(t *testing.T) {
	_, err := db.Connect("not-a-valid-postgres-url", 0)
	if err == nil {
		t.Fatal("expected error for malformed connection URL")
	}
}

func TestConnect_UnreachableHost_ReturnsError(t *testing.T) {
	_, err := db.Connect("postgres://invalid:invalid@127.0.0.1:1/nodb?connect_timeout=1", 0)
	if err == nil {
		t.Fatal("expected error when the database is unreachable (ping should fail)")
	}
}

func TestConnect_MaxConnsApplied(t *testing.T) {
	// A valid-looking URL that ParseConfig accepts but Ping will still fail
	// against (nothing listens on port 1) — this exercises the maxConns > 0
	// branch before the expected ping failure.
	_, err := db.Connect("postgres://invalid:invalid@127.0.0.1:1/nodb?connect_timeout=1", 5)
	if err == nil {
		t.Fatal("expected ping error for unreachable host even with maxConns set")
	}
}

func TestMigrate_DBError_ReturnsWrappedError(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://invalid:invalid@127.0.0.1:1/nodb?connect_timeout=1")
	if err != nil {
		t.Skip("cannot create pool stub:", err)
	}
	t.Cleanup(pool.Close)

	err = db.Migrate(pool)
	if err == nil {
		t.Fatal("expected Migrate to return an error when the DB is unreachable")
	}
}
