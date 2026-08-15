package db

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestNew_InvalidURL exercises the parse-error branch of New without
// requiring a live database.
func TestNew_InvalidURL(t *testing.T) {
	ctx := context.Background()
	d, err := New(ctx, "://not-a-valid-url", 0)
	if err == nil {
		t.Fatal("New: expected error for malformed URL, got nil")
	}
	if d != nil {
		t.Fatalf("New: expected nil DB on error, got %+v", d)
	}
	if !strings.Contains(err.Error(), "parse db url") {
		t.Fatalf("New: error = %q, want it to mention \"parse db url\"", err.Error())
	}
}

// TestNew_UnreachableHost exercises the ping-failure branch: the URL
// parses fine but nothing is listening, so the initial Ping must fail
// and the pool must be closed rather than leaked.
func TestNew_UnreachableHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	// Port 1 is reserved/unassigned; connection attempts fail fast.
	d, err := New(ctx, "postgres://user:pass@127.0.0.1:1/nodb?sslmode=disable&connect_timeout=1", 2)
	if err == nil {
		t.Fatal("New: expected error for unreachable host, got nil")
	}
	if d != nil {
		t.Fatalf("New: expected nil DB on error, got %+v", d)
	}
	if !strings.Contains(err.Error(), "initial ping") {
		t.Fatalf("New: error = %q, want it to mention \"initial ping\"", err.Error())
	}
}

// TestDB_Close_Nil verifies Close is nil-safe (used defensively by
// callers during shutdown paths where DB may not have been set up).
func TestDB_Close_Nil(t *testing.T) {
	var d *DB
	d.Close() // must not panic

	d = &DB{}
	d.Close() // must not panic with a nil Pool either
}
