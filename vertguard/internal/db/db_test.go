package db

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNew_InvalidURL(t *testing.T) {
	// A malformed connection string must fail during pgxpool.ParseConfig,
	// before any network I/O — this must return quickly and with a
	// wrapped "parse db url" error.
	_, err := New(context.Background(), "://not-a-valid-url", 10, 0)
	if err == nil {
		t.Fatal("New() error = nil, want error for malformed URL")
	}
	if !strings.Contains(err.Error(), "parse db url") {
		t.Errorf("error = %v, want it to be wrapped as \"parse db url\"", err)
	}
}

func TestNew_UnreachableHost(t *testing.T) {
	// A well-formed URL pointing at a host that refuses connections
	// should fail the initial ping rather than hang. Use a short overall
	// deadline so this test stays fast even if pgx retries internally.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := New(ctx, "postgres://user:pass@127.0.0.1:1/vertguard?connect_timeout=1", 5, 0)
	if err == nil {
		t.Fatal("New() error = nil, want error connecting to an unreachable host")
	}
}

func TestDB_Close_NilSafe(t *testing.T) {
	// Close on a nil *DB, and on a *DB with a nil Pool, must not panic —
	// shutdown paths call Close() unconditionally.
	var d *DB
	d.Close()

	d2 := &DB{}
	d2.Close()
}

func TestNullIfEmpty(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want any
	}{
		{"empty string becomes nil", "", nil},
		{"non-empty string passes through", "hello", "hello"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nullIfEmpty(tt.in)
			if got != tt.want {
				t.Errorf("nullIfEmpty(%q) = %#v, want %#v", tt.in, got, tt.want)
			}
		})
	}
}

func TestListAuditEvents_InvalidCursor(t *testing.T) {
	// A malformed sinceID cursor must be rejected during uuid.Parse,
	// before the query ever touches the pool — verified here by using a
	// DB with a nil Pool: if the code tried to reach the pool first, this
	// would panic instead of returning a clean error.
	d := &DB{}
	_, err := d.ListAuditEvents(context.Background(), 10, "not-a-uuid")
	if err == nil {
		t.Fatal("ListAuditEvents() error = nil, want error for invalid cursor")
	}
	if !strings.Contains(err.Error(), "parse cursor") {
		t.Errorf("error = %v, want it to be wrapped as \"parse cursor\"", err)
	}
}
