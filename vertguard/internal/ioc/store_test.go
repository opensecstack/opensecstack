//go:build integration

package ioc

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// requireDB skips the test when VERTGUARD_TEST_DB_URL is unset — same
// gating pattern the rest of the integration suite uses.
func requireDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("VERTGUARD_TEST_DB_URL")
	if url == "" {
		t.Skip("VERTGUARD_TEST_DB_URL not set — skipping IOC store integration test")
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
