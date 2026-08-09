package db

import (
	"context"
	"errors"
	"testing"
)

func TestOpen_InvalidDSNReturnsError(t *testing.T) {
	_, err := Open(context.Background(), "://not a valid dsn", 4)
	if err == nil {
		t.Fatal("expected an error for a malformed DSN")
	}
}

func TestOpen_ValidDSNBuildsPoolWithMaxConns(t *testing.T) {
	// pgxpool.NewWithConfig only parses and configures the pool; it does not
	// eagerly connect, so a syntactically valid DSN succeeds even with no
	// reachable database.
	pool, err := Open(context.Background(), "postgres://user:pass@127.0.0.1:1/db", 7)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer pool.Close()

	if got := pool.Config().MaxConns; got != 7 {
		t.Errorf("MaxConns = %d, want 7", got)
	}
}

func TestOpen_ZeroMaxConnsKeepsPoolDefault(t *testing.T) {
	pool, err := Open(context.Background(), "postgres://user:pass@127.0.0.1:1/db", 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer pool.Close()

	// maxConns<=0 must not force MaxConns to 0 (which would make the pool
	// unusable) — pgxpool's own default should remain in effect.
	if pool.Config().MaxConns == 0 {
		t.Errorf("MaxConns = 0, want pgxpool default to be preserved when maxConns<=0")
	}
}

func TestErrNotFoundAndErrConflictAreDistinct(t *testing.T) {
	if errors.Is(ErrNotFound, ErrConflict) {
		t.Fatal("ErrNotFound and ErrConflict must be distinct sentinels")
	}
}
