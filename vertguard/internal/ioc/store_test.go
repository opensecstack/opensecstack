package ioc

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// requireDB skips the test when DATABASE_URL is unset — same
// gating pattern the rest of the integration suite uses.
func requireDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set — skipping IOC store integration test")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestStoreUpsertAndList(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()
	tenant := "vg-test-" + time.Now().Format("150405")

	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM iocs WHERE tenant=$1`, tenant)
		_, _ = pool.Exec(ctx, `DELETE FROM ioc_pull_audit WHERE source LIKE 'test-%'`)
	})

	row := IOC{Kind: KindIP, Value: "198.51.100.7", Source: "test-src",
		Confidence: 0.6, Tenant: tenant}
	if r, err := s.Upsert(ctx, row); err != nil || r != UpsertInserted {
		t.Fatalf("first upsert: r=%v err=%v", r, err)
	}
	row.Confidence = 0.9
	if r, err := s.Upsert(ctx, row); err != nil || r != UpsertUpdated {
		t.Fatalf("second upsert: r=%v err=%v", r, err)
	}

	got, _, err := s.List(ctx, ListFilter{Tenant: tenant, Limit: 10})
	if err != nil || len(got) != 1 {
		t.Fatalf("list: n=%d err=%v", len(got), err)
	}
	if got[0].Confidence < 0.85 {
		t.Errorf("confidence not bumped: %v", got[0].Confidence)
	}
}

func TestStoreExpireSweep(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()
	tenant := "vg-test-sweep-" + time.Now().Format("150405")
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM iocs WHERE tenant=$1`, tenant) })

	past := time.Now().Add(-time.Hour)
	if _, err := s.Upsert(ctx, IOC{Kind: KindDomain, Value: "old.example",
		Source: "test", Tenant: tenant, ExpiresAt: &past}); err != nil {
		t.Fatal(err)
	}
	n, err := s.ExpireSweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Errorf("want >=1 deleted, got %d", n)
	}
}

func TestStoreAuditInsert(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM ioc_pull_audit WHERE source='test-audit'`) })

	if err := s.AuditInsert(ctx, PullAudit{
		Source: "test-audit", StartedAt: time.Now(), FinishedAt: time.Now(),
		Fetched: 3, Inserted: 2, Skipped: 1,
	}); err != nil {
		t.Fatalf("audit insert: %v", err)
	}
}

func TestStoreAuditInsert_WithErrorField(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM ioc_pull_audit WHERE source='test-audit-err'`) })

	if err := s.AuditInsert(ctx, PullAudit{
		Source: "test-audit-err", StartedAt: time.Now(), FinishedAt: time.Now(),
		Error: "upstream timeout",
	}); err != nil {
		t.Fatalf("audit insert with error field: %v", err)
	}
}

func TestNewStore_NilPoolReturnsNil(t *testing.T) {
	if s := NewStore(nil); s != nil {
		t.Fatalf("NewStore(nil) = %v, want nil", s)
	}
}

func TestStore_GetByValue_NotFound(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	_, err := s.GetByValue(ctx, KindIP, "192.0.2.1", "no-such-tenant-"+time.Now().Format("150405.000000"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetByValue() error = %v, want ErrNotFound", err)
	}
}

func TestStore_List_FiltersAndPagination(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()
	tenant := "vg-test-list-" + time.Now().Format("150405.000000")
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM iocs WHERE tenant=$1`, tenant) })

	rows := []IOC{
		{Kind: KindIP, Value: "198.51.100.1", Source: "src-a", Tenant: tenant},
		{Kind: KindIP, Value: "198.51.100.2", Source: "src-b", Tenant: tenant},
		{Kind: KindDomain, Value: "evil-a.example", Source: "src-a", Tenant: tenant},
	}
	for _, r := range rows {
		if _, err := s.Upsert(ctx, r); err != nil {
			t.Fatalf("seed upsert: %v", err)
		}
	}

	// Filter by kind.
	got, _, err := s.List(ctx, ListFilter{Tenant: tenant, Kind: string(KindIP), Limit: 10})
	if err != nil {
		t.Fatalf("list by kind: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("list by kind: got %d rows, want 2", len(got))
	}

	// Filter by source.
	got, _, err = s.List(ctx, ListFilter{Tenant: tenant, Source: "src-a", Limit: 10})
	if err != nil {
		t.Fatalf("list by source: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("list by source: got %d rows, want 2", len(got))
	}

	// Pagination: limit=1 should report a next cursor and return exactly 1 row.
	got, next, err := s.List(ctx, ListFilter{Tenant: tenant, Limit: 1})
	if err != nil {
		t.Fatalf("list paginated: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("list paginated: got %d rows, want 1", len(got))
	}
	if next != 1 {
		t.Fatalf("list paginated: next cursor = %d, want 1", next)
	}

	// Negative cursor and non-positive limit both get clamped to defaults.
	got, _, err = s.List(ctx, ListFilter{Tenant: tenant, Cursor: -5, Limit: 0})
	if err != nil {
		t.Fatalf("list with clamped params: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("list with clamped params: got %d rows, want 3", len(got))
	}
}

func TestStore_CountActive(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()
	tenant := "vg-test-count-" + time.Now().Format("150405.000000")
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM iocs WHERE tenant=$1`, tenant) })

	past := time.Now().Add(-time.Hour)
	if _, err := s.Upsert(ctx, IOC{Kind: KindIP, Value: "198.51.100.9", Tenant: tenant}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Upsert(ctx, IOC{Kind: KindDomain, Value: "expired.example", Tenant: tenant, ExpiresAt: &past}); err != nil {
		t.Fatal(err)
	}

	before, err := s.CountActive(ctx)
	if err != nil {
		t.Fatalf("count active: %v", err)
	}
	if before < 1 {
		t.Fatalf("count active before sweep = %d, want >=1 (the non-expired row)", before)
	}
}
