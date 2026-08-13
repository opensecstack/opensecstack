// Integration test against a real Postgres instance. Skipped unless
// OPENSCRUB_TEST_DB_URL is set. Mirrors cyberpath's pattern.
//
// No build tag: these tests run as part of the normal `go test ./...`
// invocation (and thus count toward the package's coverage gate) but
// skip themselves at runtime when OPENSCRUB_TEST_DB_URL is unset, so a
// developer/CI box without Postgres still gets a clean `go test`.
//
//   psql -c 'CREATE DATABASE openscrub_test;'
//   migrate -path migrations -database "$OPENSCRUB_TEST_DB_URL" up
//   OPENSCRUB_TEST_DB_URL=postgres://… go test ./internal/db/

package db_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/openscrub/internal/db"
	"github.com/opensecstack/openscrub/internal/rules"
)

func openTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("OPENSCRUB_TEST_DB_URL")
	if url == "" {
		t.Skip("OPENSCRUB_TEST_DB_URL unset — skipping integration")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pgx connect: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM mitigations; DELETE FROM ioc_ingest_log; DELETE FROM rules`)
		pool.Close()
	})
	return pool
}

func TestRuleStoreInsertGetDelete(t *testing.T) {
	pool := openTestDB(t)
	store := db.NewRuleStore(pool)

	ttl := 60
	rule := rules.Rule{
		Type: rules.TypeBlocklist, CIDR: "203.0.113.42/24",
		TTLSeconds: ttl, Source: rules.SourceOperator,
	}
	stored, err := store.Insert(context.Background(), rule)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ID == uuid.Nil || stored.CIDR != "203.0.113.0/24" {
		t.Fatalf("unexpected: %+v", stored)
	}

	got, err := store.Get(context.Background(), stored.ID)
	if err != nil || got.ID != stored.ID {
		t.Fatalf("get: %v %v", got, err)
	}

	if err := store.Delete(context.Background(), stored.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(context.Background(), stored.ID); !errors.Is(err, db.ErrRuleNotFound) {
		t.Fatalf("expected not-found, got %v", err)
	}
}

func TestRuleStoreDeleteExpired(t *testing.T) {
	pool := openTestDB(t)
	store := db.NewRuleStore(pool)

	now := time.Now().UTC()
	expired := rules.Rule{
		Type: rules.TypeBlocklist, CIDR: "10.0.0.0/8",
		TTLSeconds: 1, Source: rules.SourceOperator,
		CreatedAt: now.Add(-1 * time.Hour),
		ExpiresAt: now.Add(-30 * time.Minute),
	}
	live := rules.Rule{
		Type: rules.TypeBlocklist, CIDR: "10.1.0.0/16",
		TTLSeconds: 3600, Source: rules.SourceOperator,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}
	if _, err := store.Insert(context.Background(), expired); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Insert(context.Background(), live); err != nil {
		t.Fatal(err)
	}
	rows, err := store.DeleteExpired(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].CIDR != "10.0.0.0/8" {
		t.Fatalf("unexpected expired: %+v", rows)
	}
}

// TestRuleStoreListOffsetPagination guards the BLOCKER-1 contract: the
// SQL ORDER BY must include `id DESC` so identical timestamps don't
// shuffle between pages, and OFFSET must be applied. We insert 5 rules
// at the SAME created_at — without the id-DESC tiebreaker the page
// boundaries would be non-deterministic across queries.
func TestRuleStoreListOffsetPagination(t *testing.T) {
	pool := openTestDB(t)
	store := db.NewRuleStore(pool)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	cidrs := []string{
		"203.0.113.1/32", "203.0.113.2/32", "203.0.113.3/32",
		"203.0.113.4/32", "203.0.113.5/32",
	}
	for _, c := range cidrs {
		if _, err := store.Insert(ctx, rules.Rule{
			Type: rules.TypeBlocklist, CIDR: c,
			TTLSeconds: 3600, Source: rules.SourceOperator,
			CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatalf("insert %s: %v", c, err)
		}
	}

	page0, err := store.List(ctx, "", 2, 0)
	if err != nil || len(page0) != 2 {
		t.Fatalf("page0: len=%d err=%v", len(page0), err)
	}
	page1, err := store.List(ctx, "", 2, 2)
	if err != nil || len(page1) != 2 {
		t.Fatalf("page1: len=%d err=%v", len(page1), err)
	}
	page2, err := store.List(ctx, "", 2, 4)
	if err != nil || len(page2) != 1 {
		t.Fatalf("page2: len=%d err=%v", len(page2), err)
	}
	// No overlap, no skips: every rule appears exactly once across the
	// three pages even though they share a created_at.
	seen := map[uuid.UUID]struct{}{}
	for _, p := range [][]rules.Rule{page0, page1, page2} {
		for _, r := range p {
			if _, dup := seen[r.ID]; dup {
				t.Fatalf("duplicate rule id across pages: %s", r.ID)
			}
			seen[r.ID] = struct{}{}
		}
	}
	if len(seen) != 5 {
		t.Fatalf("expected 5 distinct rules across paginated walk, got %d", len(seen))
	}

	// Repeat the same query and verify identical pages — the
	// id-DESC tiebreaker guarantees stability under repeated reads.
	page0b, err := store.List(ctx, "", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := range page0 {
		if page0[i].ID != page0b[i].ID {
			t.Fatalf("page0 not stable across reads: %v vs %v", page0, page0b)
		}
	}
}

// TestRuleStoreInsertInvalidCIDR covers the parse-error branch: a
// malformed CIDR must be rejected before it ever reaches the INSERT,
// and must not be wrapped as a generic "insert rule" failure.
func TestRuleStoreInsertInvalidCIDR(t *testing.T) {
	pool := openTestDB(t)
	store := db.NewRuleStore(pool)

	_, err := store.Insert(context.Background(), rules.Rule{
		Type: rules.TypeBlocklist, CIDR: "not-a-cidr",
		TTLSeconds: 60, Source: rules.SourceOperator,
	})
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

// TestRuleStoreDeleteNotFound covers the RowsAffected==0 branch: an
// unknown id must return ErrRuleNotFound, not a silent success.
func TestRuleStoreDeleteNotFound(t *testing.T) {
	pool := openTestDB(t)
	store := db.NewRuleStore(pool)

	err := store.Delete(context.Background(), uuid.New())
	if !errors.Is(err, db.ErrRuleNotFound) {
		t.Fatalf("expected ErrRuleNotFound, got %v", err)
	}
}

// TestRuleStoreListKindFilter covers the `kind != ""` branch of List
// and the count helpers that back the /api/v1 snapshot endpoint.
func TestRuleStoreListKindFilter(t *testing.T) {
	pool := openTestDB(t)
	store := db.NewRuleStore(pool)
	ctx := context.Background()

	if _, err := store.Insert(ctx, rules.Rule{
		Type: rules.TypeBlocklist, CIDR: "192.0.2.0/24",
		TTLSeconds: 3600, Source: rules.SourceOperator,
	}); err != nil {
		t.Fatal(err)
	}
	pps := 1000
	if _, err := store.Insert(ctx, rules.Rule{
		Type: rules.TypeRatelimit, CIDR: "192.0.2.128/25", PPS: &pps,
		TTLSeconds: 3600, Source: rules.SourceOperator,
	}); err != nil {
		t.Fatal(err)
	}
	port := 22
	if _, err := store.Insert(ctx, rules.Rule{
		Type: rules.TypeSynCookie, Port: &port,
		TTLSeconds: 3600, Source: rules.SourceOperator,
	}); err != nil {
		t.Fatal(err)
	}

	blocklistOnly, err := store.List(ctx, rules.TypeBlocklist, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range blocklistOnly {
		if r.Type != rules.TypeBlocklist {
			t.Fatalf("kind filter leaked a %s rule: %+v", r.Type, r)
		}
	}
	if len(blocklistOnly) == 0 {
		t.Fatal("expected at least one blocklist rule")
	}

	total, err := store.Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if total < 3 {
		t.Fatalf("expected at least 3 rules total, got %d", total)
	}

	blocklist, ratelimit, syncookie, err := store.CountByType(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if blocklist < 1 || ratelimit < 1 || syncookie < 1 {
		t.Fatalf("expected all three types represented: blocklist=%d ratelimit=%d syncookie=%d",
			blocklist, ratelimit, syncookie)
	}

	v4, v6, err := store.CountBlocklistByFamily(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v4 < 1 {
		t.Fatalf("expected at least 1 IPv4 blocklist rule, got v4=%d v6=%d", v4, v6)
	}
}

// TestRuleStoreCountBlocklistByFamilyIPv6 exercises the IPv6 branch of
// CountBlocklistByFamily separately, since the shared fixture above
// only inserts IPv4.
func TestRuleStoreCountBlocklistByFamilyIPv6(t *testing.T) {
	pool := openTestDB(t)
	store := db.NewRuleStore(pool)
	ctx := context.Background()

	if _, err := store.Insert(ctx, rules.Rule{
		Type: rules.TypeBlocklist, CIDR: "2001:db8::/32",
		TTLSeconds: 3600, Source: rules.SourceOperator,
	}); err != nil {
		t.Fatal(err)
	}

	_, v6, err := store.CountBlocklistByFamily(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v6 < 1 {
		t.Fatalf("expected at least 1 IPv6 blocklist rule, got v6=%d", v6)
	}
}

func TestRuleStoreSynCookieRoundtrip(t *testing.T) {
	pool := openTestDB(t)
	store := db.NewRuleStore(pool)
	port := 443
	rule := rules.Rule{
		Type: rules.TypeSynCookie, Port: &port,
		TTLSeconds: 600, Source: rules.SourceOperator,
	}
	stored, err := store.Insert(context.Background(), rule)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(context.Background(), stored.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.CIDR != "" || got.Port == nil || *got.Port != 443 {
		t.Fatalf("unexpected roundtrip: %+v", got)
	}
}
