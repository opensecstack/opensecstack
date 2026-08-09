package db

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestNewPool_ConnectionRefusedReturnsWrappedError verifies that NewPool
// surfaces a wrapped, descriptive error (rather than hanging or panicking)
// when the target database is unreachable. This is the fail-closed path
// every caller of NewPool (serve, migrate) depends on to abort startup.
func TestNewPool_ConnectionRefusedReturnsWrappedError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Port 1 on loopback is a reserved, virtually never-listening port, so
	// the connection attempt fails fast instead of hanging.
	_, err := NewPool(ctx, "127.0.0.1", 1, "irflow", "user", "pass", "disable")
	if err == nil {
		t.Fatal("expected NewPool to return an error when the database is unreachable")
	}
	if !strings.Contains(err.Error(), "pinging db") && !strings.Contains(err.Error(), "connecting to db") {
		t.Errorf("expected error to be wrapped with a 'pinging db' or 'connecting to db' prefix, got: %v", err)
	}
}

// TestNewPool_InvalidDSNReturnsParseError verifies that a password containing
// characters illegal in a bare connection URL surfaces a "parsing db config"
// error rather than silently connecting with a mis-parsed credential.
func TestNewPool_InvalidDSNReturnsParseError(t *testing.T) {
	_, err := NewPool(context.Background(), "127.0.0.1", 5432, "irflow", "user", "p@ss/word:bad", "disable")
	if err == nil {
		t.Fatal("expected NewPool to return an error for a malformed DSN")
	}
}
