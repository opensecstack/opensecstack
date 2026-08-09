package db

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ── New ──────────────────────────────────────────────────────────────────────

// TestNew_InvalidConnStringFailsAtParse confirms New rejects a malformed
// connection string during ParseConfig, before ever attempting to dial —
// the error must be wrapped with the "parsing connection string" context so
// callers (and operators reading logs) can tell a config typo apart from a
// genuine network/auth failure.
func TestNew_InvalidConnStringFailsAtParse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	d, err := New(ctx, "not a valid connection string://???")
	if err == nil {
		t.Fatal("expected error for malformed connection string, got nil")
	}
	if d != nil {
		t.Error("expected nil *DB on parse error")
	}
	if !strings.Contains(err.Error(), "parsing connection string") {
		t.Errorf("expected 'parsing connection string' in error, got: %v", err)
	}
}

// TestNew_UnreachableHostFailsAtPing confirms New's explicit Ping-on-connect
// behavior: given a syntactically valid DSN pointing at a host refusing
// connections, New must fail (not silently return a pool that will only
// error on first real query later) and must close the pool it opened before
// returning the error — verified indirectly here by confirming the returned
// *DB is nil (a leaked, half-open pool would still be usable by a careless
// caller who ignored the error).
func TestNew_UnreachableHostFailsAtPing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	d, err := New(ctx, "postgres://citadel:citadel@127.0.0.1:1/citadel?sslmode=disable&connect_timeout=2")
	if err == nil {
		t.Fatal("expected error connecting to an unreachable host, got nil")
	}
	if d != nil {
		t.Error("expected nil *DB when ping fails")
	}
	if !strings.Contains(err.Error(), "pinging database") {
		t.Errorf("expected 'pinging database' in error, got: %v", err)
	}
}

// ── Close / Ping ─────────────────────────────────────────────────────────────

// unreachablePool returns a lazily-connecting pool aimed at a port that
// actively refuses connections (nothing listens on 127.0.0.1:1), so calls
// against it fail fast with a real, non-simulated connection error rather
// than hanging until a context deadline.
func unreachablePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), "postgres://citadel:citadel@127.0.0.1:1/citadel?sslmode=disable&connect_timeout=2")
	if err != nil {
		t.Fatalf("pgxpool.New (lazy, should not dial): %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestDB_Ping_UnreachableReturnsError(t *testing.T) {
	d := &DB{Pool: unreachablePool(t)}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := d.Ping(ctx); err == nil {
		t.Fatal("expected Ping to error against an unreachable database")
	}
}

func TestDB_Close_DoesNotPanicOnLazyPool(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://citadel:citadel@127.0.0.1:1/citadel?sslmode=disable")
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	d := &DB{Pool: pool}

	// Close must be safe to call even though the pool never successfully
	// connected — it must not panic or block.
	d.Close()
}
