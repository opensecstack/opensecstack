//go:build integration

// Integration tests for internal/correlate exercise every rule against a real
// Postgres instance — the raw SQL in correlate.go (inet casts, LIKE suffix
// matching, JSONB evidence) cannot be verified with a mock. Run with:
//
//	THREATFLOW_TEST_DB_URL=postgres://... go test -tags=integration ./internal/correlate/...
package correlate

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/rs/zerolog"

	"github.com/opensecstack/threatflow/internal/db/store"
)

// testDB wires a pool for correlate integration tests. Modeled closely on
// internal/db/store/integration_helper_test.go — that helper's testDB is
// unexported to package store, so correlate needs its own copy. Skips
// cleanly when THREATFLOW_TEST_DB_URL is unset so plain `go test ./...`
// stays fast and DB-free.
func testDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("THREATFLOW_TEST_DB_URL")
	if dsn == "" {
		t.Skip("THREATFLOW_TEST_DB_URL not set; skipping integration tests")
	}

	runMigrations(t, dsn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)

	truncate(t, pool)
	return pool
}

// runMigrations applies every migration from internal/db/migrations. Path is
// relative to this package (internal/correlate), one level up from
// internal/db/store's own helper.
func runMigrations(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql open: %v", err)
	}
	defer db.Close()

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		t.Fatalf("driver: %v", err)
	}
	mig, err := migrate.NewWithDatabaseInstance(
		"file://../db/migrations",
		"postgres", driver,
	)
	if err != nil {
		t.Fatalf("migrate init: %v", err)
	}
	if err := mig.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("migrate up: %v", err)
	}
}

// truncate wipes every mutable table between tests, matching the table list
// in store's helper so leftover rows never leak across cases.
func truncate(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx, `
TRUNCATE TABLE
  ioc_correlations,
  ttp_tags,
  sightings,
  advisory_remediations,
  advisory_vulnerabilities,
  advisory_products,
  advisory_revisions,
  advisories,
  stix_objects,
  stix_bundles,
  iocs,
  feeds,
  webhook_deliveries,
  webhook_subscribers,
  api_keys
RESTART IDENTITY CASCADE`)
	if err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

// seedOpts describes an iocs row to insert directly (bypassing any ingest
// pipeline) so each rule can be exercised in isolation.
type seedOpts struct {
	Type   string
	Value  string
	FeedID *uuid.UUID
	Source string
	CVE    string
}

func seedFeed(t *testing.T, pool *pgxpool.Pool, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(context.Background(), `
INSERT INTO feeds (name, feed_type) VALUES ($1, 'manual') RETURNING id`, name).Scan(&id)
	if err != nil {
		t.Fatalf("seed feed %q: %v", name, err)
	}
	return id
}

func seedIOC(t *testing.T, pool *pgxpool.Pool, o seedOpts) *store.IOC {
	t.Helper()
	id := uuid.New()
	stixID := fmt.Sprintf("indicator--%s", id)
	pattern := fmt.Sprintf("[%s:value = '%s']", o.Type, o.Value)
	patternHash := id.String() // unique per row, content irrelevant to the rules under test

	_, err := pool.Exec(context.Background(), `
INSERT INTO iocs (id, stix_id, type, value, pattern, pattern_hash, feed_id, source, cve)
VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), NULLIF($9, ''))`,
		id, stixID, o.Type, o.Value, pattern, patternHash, o.FeedID, o.Source, o.CVE)
	if err != nil {
		t.Fatalf("seed ioc %q/%q: %v", o.Type, o.Value, err)
	}
	return &store.IOC{ID: id, Type: o.Type, Value: o.Value, FeedID: o.FeedID, Source: o.Source, CVE: o.CVE}
}

func newTestEngine(pool *pgxpool.Pool) (*Engine, *store.CorrelationStore) {
	corr := store.NewCorrelationStore(pool)
	return New(pool, corr, zerolog.Nop()), corr
}

// findRelationship returns the neighbor entries touching sourceID with the
// given relationship, in either direction.
func findRelationship(t *testing.T, corr *store.CorrelationStore, id uuid.UUID, relationship string) []*store.CorrelationNeighbor {
	t.Helper()
	neighbors, err := corr.ForIOC(context.Background(), id)
	if err != nil {
		t.Fatalf("ForIOC: %v", err)
	}
	var out []*store.CorrelationNeighbor
	for _, n := range neighbors {
		if n.Relationship == relationship {
			out = append(out, n)
		}
	}
	return out
}

// TestRuleCrossFeedDuplicate_Integration proves two IOCs sharing type+value
// but ingested from different feeds are linked as "duplicate" with the
// expected evidence payload.
func TestRuleCrossFeedDuplicate_Integration(t *testing.T) {
	pool := testDB(t)
	e, corr := newTestEngine(pool)
	ctx := context.Background()

	feedA := seedFeed(t, pool, "feed-a")
	feedB := seedFeed(t, pool, "feed-b")

	first := seedIOC(t, pool, seedOpts{Type: "domain-name", Value: "dup.example", FeedID: &feedA, Source: "alienvault"})
	second := seedIOC(t, pool, seedOpts{Type: "domain-name", Value: "dup.example", FeedID: &feedB, Source: "otx"})

	n, err := e.ruleCrossFeedDuplicate(ctx, second)
	if err != nil {
		t.Fatalf("ruleCrossFeedDuplicate: %v", err)
	}
	if n != 1 {
		t.Fatalf("n = %d, want 1", n)
	}

	got := findRelationship(t, corr, second.ID, "duplicate")
	if len(got) != 1 {
		t.Fatalf("duplicate correlations = %d, want 1", len(got))
	}
	if got[0].Confidence != 90 {
		t.Errorf("confidence = %d, want 90", got[0].Confidence)
	}
	if got[0].OtherIOCID != first.ID {
		t.Errorf("other ioc = %s, want %s", got[0].OtherIOCID, first.ID)
	}
	var ev map[string]any
	if err := json.Unmarshal(got[0].Evidence, &ev); err != nil {
		t.Fatalf("unmarshal evidence: %v", err)
	}
	if ev["other_source"] != "alienvault" {
		t.Errorf("evidence other_source = %v, want alienvault", ev["other_source"])
	}
}

// TestRuleCrossFeedDuplicate_Integration_NoMatch proves a unique IOC produces
// no duplicate correlation and no error.
func TestRuleCrossFeedDuplicate_Integration_NoMatch(t *testing.T) {
	pool := testDB(t)
	e, _ := newTestEngine(pool)
	ctx := context.Background()

	only := seedIOC(t, pool, seedOpts{Type: "domain-name", Value: "lonely.example"})
	n, err := e.ruleCrossFeedDuplicate(ctx, only)
	if err != nil {
		t.Fatalf("ruleCrossFeedDuplicate: %v", err)
	}
	if n != 0 {
		t.Fatalf("n = %d, want 0", n)
	}
}

// TestRuleURLResolvesToDomain_Integration covers both match tiers: a URL
// whose host exactly equals a known domain IOC, and one whose host is a
// subdomain (suffix match) of a known domain IOC.
func TestRuleURLResolvesToDomain_Integration(t *testing.T) {
	pool := testDB(t)
	e, corr := newTestEngine(pool)
	ctx := context.Background()

	exactDomain := seedIOC(t, pool, seedOpts{Type: "domain-name", Value: "bank.example"})
	suffixDomain := seedIOC(t, pool, seedOpts{Type: "domain-name", Value: "evil.example"})

	exactURL := seedIOC(t, pool, seedOpts{Type: "url", Value: "http://bank.example/login"})
	n, err := e.ruleURLResolvesToDomain(ctx, exactURL)
	if err != nil {
		t.Fatalf("ruleURLResolvesToDomain (exact): %v", err)
	}
	if n != 1 {
		t.Fatalf("n = %d, want 1 (exact)", n)
	}
	got := findRelationship(t, corr, exactURL.ID, "resolves-to")
	if len(got) != 1 || got[0].OtherIOCID != exactDomain.ID {
		t.Fatalf("exact-match resolves-to = %+v, want target %s", got, exactDomain.ID)
	}
	if got[0].Confidence != 80 {
		t.Errorf("confidence = %d, want 80", got[0].Confidence)
	}

	suffixURL := seedIOC(t, pool, seedOpts{Type: "url", Value: "https://login.evil.example:8443/x"})
	n, err = e.ruleURLResolvesToDomain(ctx, suffixURL)
	if err != nil {
		t.Fatalf("ruleURLResolvesToDomain (suffix): %v", err)
	}
	if n != 1 {
		t.Fatalf("n = %d, want 1 (suffix)", n)
	}
	got = findRelationship(t, corr, suffixURL.ID, "resolves-to")
	if len(got) != 1 || got[0].OtherIOCID != suffixDomain.ID {
		t.Fatalf("suffix-match resolves-to = %+v, want target %s", got, suffixDomain.ID)
	}
	var ev map[string]any
	if err := json.Unmarshal(got[0].Evidence, &ev); err != nil {
		t.Fatalf("unmarshal evidence: %v", err)
	}
	if ev["host"] != "login.evil.example" {
		t.Errorf("evidence host = %v, want login.evil.example", ev["host"])
	}
}

// TestRuleURLResolvesToDomain_Integration_UnparsableURL proves the
// hostFromURL("") short-circuit skips the query entirely.
func TestRuleURLResolvesToDomain_Integration_UnparsableURL(t *testing.T) {
	pool := testDB(t)
	e, _ := newTestEngine(pool)
	ctx := context.Background()

	bad := seedIOC(t, pool, seedOpts{Type: "url", Value: "not-a-url"})
	n, err := e.ruleURLResolvesToDomain(ctx, bad)
	if err != nil {
		t.Fatalf("ruleURLResolvesToDomain: %v", err)
	}
	if n != 0 {
		t.Fatalf("n = %d, want 0", n)
	}
}

// TestRuleDomainSubdomain_Integration proves "www.example.com" links to a
// pre-existing "example.com" IOC as subdomain-of.
func TestRuleDomainSubdomain_Integration(t *testing.T) {
	pool := testDB(t)
	e, corr := newTestEngine(pool)
	ctx := context.Background()

	parent := seedIOC(t, pool, seedOpts{Type: "domain-name", Value: "example.com"})
	child := seedIOC(t, pool, seedOpts{Type: "domain-name", Value: "www.example.com"})

	n, err := e.ruleDomainSubdomain(ctx, child)
	if err != nil {
		t.Fatalf("ruleDomainSubdomain: %v", err)
	}
	if n != 1 {
		t.Fatalf("n = %d, want 1", n)
	}
	got := findRelationship(t, corr, child.ID, "subdomain-of")
	if len(got) != 1 || got[0].OtherIOCID != parent.ID {
		t.Fatalf("subdomain-of = %+v, want target %s", got, parent.ID)
	}
	if got[0].Confidence != 85 {
		t.Errorf("confidence = %d, want 85", got[0].Confidence)
	}
}

// TestRuleDomainSubdomain_Integration_NoDot proves a bare label (no ".")
// short-circuits without querying.
func TestRuleDomainSubdomain_Integration_NoDot(t *testing.T) {
	pool := testDB(t)
	e, _ := newTestEngine(pool)
	ctx := context.Background()

	bare := seedIOC(t, pool, seedOpts{Type: "domain-name", Value: "localhost"})
	n, err := e.ruleDomainSubdomain(ctx, bare)
	if err != nil {
		t.Fatalf("ruleDomainSubdomain: %v", err)
	}
	if n != 0 {
		t.Fatalf("n = %d, want 0", n)
	}
}

// TestRuleIPSameNetwork_Integration exercises ruleIPSameNetwork end-to-end.
// The iocs.value column is TEXT, so the `value <<= $2::inet` comparison in
// the primary path errs in Postgres (no implicit text->inet cast) and the
// method silently falls back to ruleIPSameNetworkFallback's LIKE-based
// match — this test asserts the observable result is correct regardless of
// which internal path served it, and logs which one fired.
func TestRuleIPSameNetwork_Integration(t *testing.T) {
	pool := testDB(t)
	e, corr := newTestEngine(pool)
	ctx := context.Background()

	// Empirically confirm which path Postgres takes for this schema.
	var probeErr error
	func() {
		rows, err := pool.Query(ctx, `SELECT 1 FROM iocs WHERE value <<= $1::inet LIMIT 1`, "10.0.0.0/24")
		if err != nil {
			probeErr = err
			return
		}
		rows.Close()
	}()
	if probeErr != nil {
		t.Logf("primary inet-cast path errors as expected (%v); ruleIPSameNetwork falls back", probeErr)
	} else {
		t.Logf("primary inet-cast path succeeded; fallback not exercised by ruleIPSameNetwork itself")
	}

	source := seedIOC(t, pool, seedOpts{Type: "ipv4-addr", Value: "10.0.0.5"})
	sameNet := seedIOC(t, pool, seedOpts{Type: "ipv4-addr", Value: "10.0.0.9"})
	otherNet := seedIOC(t, pool, seedOpts{Type: "ipv4-addr", Value: "10.0.1.5"})

	n, err := e.ruleIPSameNetwork(ctx, source)
	if err != nil {
		t.Fatalf("ruleIPSameNetwork: %v", err)
	}
	if n != 1 {
		t.Fatalf("n = %d, want 1", n)
	}

	got := findRelationship(t, corr, source.ID, "same-network")
	if len(got) != 1 || got[0].OtherIOCID != sameNet.ID {
		t.Fatalf("same-network = %+v, want target %s (not %s)", got, sameNet.ID, otherNet.ID)
	}
	if got[0].Confidence != 60 {
		t.Errorf("confidence = %d, want 60", got[0].Confidence)
	}
}

// TestRuleIPSameNetwork_Integration_InvalidIP proves a malformed IP value
// short-circuits via the net.ParseCIDR failure branch.
func TestRuleIPSameNetwork_Integration_InvalidIP(t *testing.T) {
	pool := testDB(t)
	e, _ := newTestEngine(pool)
	ctx := context.Background()

	bad := seedIOC(t, pool, seedOpts{Type: "ipv4-addr", Value: "not-an-ip"})
	n, err := e.ruleIPSameNetwork(ctx, bad)
	if err != nil {
		t.Fatalf("ruleIPSameNetwork: %v", err)
	}
	if n != 0 {
		t.Fatalf("n = %d, want 0", n)
	}
}

// TestRuleIPSameNetworkFallback_Integration calls the text-LIKE fallback
// path directly so it is exercised regardless of whether the primary
// inet-cast path happens to succeed on a given Postgres version.
func TestRuleIPSameNetworkFallback_Integration(t *testing.T) {
	pool := testDB(t)
	e, corr := newTestEngine(pool)
	ctx := context.Background()

	source := seedIOC(t, pool, seedOpts{Type: "ipv4-addr", Value: "192.168.5.1"})
	sameNet := seedIOC(t, pool, seedOpts{Type: "ipv4-addr", Value: "192.168.5.200"})
	_ = seedIOC(t, pool, seedOpts{Type: "ipv4-addr", Value: "192.168.6.1"})

	n, err := e.ruleIPSameNetworkFallback(ctx, source, "192.168.5.0/24")
	if err != nil {
		t.Fatalf("ruleIPSameNetworkFallback: %v", err)
	}
	if n != 1 {
		t.Fatalf("n = %d, want 1", n)
	}
	got := findRelationship(t, corr, source.ID, "same-network")
	if len(got) != 1 || got[0].OtherIOCID != sameNet.ID {
		t.Fatalf("same-network = %+v, want target %s", got, sameNet.ID)
	}
}

// TestRuleIPSameNetworkFallback_Integration_MalformedPrefix proves a prefix
// that doesn't split into 4 octets (defensive branch — ruleIPSameNetwork
// always passes a valid /24 string, but the helper guards independently)
// returns zero without querying.
func TestRuleIPSameNetworkFallback_Integration_MalformedPrefix(t *testing.T) {
	pool := testDB(t)
	e, _ := newTestEngine(pool)
	ctx := context.Background()

	source := seedIOC(t, pool, seedOpts{Type: "ipv4-addr", Value: "10.0.0.5"})
	n, err := e.ruleIPSameNetworkFallback(ctx, source, "not-a-prefix")
	if err != nil {
		t.Fatalf("ruleIPSameNetworkFallback: %v", err)
	}
	if n != 0 {
		t.Fatalf("n = %d, want 0", n)
	}
}

// TestRuleSharedCVE_Integration proves two IOCs of different types carrying
// the same CVE identifier are linked as shares-cve.
func TestRuleSharedCVE_Integration(t *testing.T) {
	pool := testDB(t)
	e, corr := newTestEngine(pool)
	ctx := context.Background()

	url := seedIOC(t, pool, seedOpts{Type: "url", Value: "http://exploit.example/poc", CVE: "CVE-2024-1234"})
	file := seedIOC(t, pool, seedOpts{Type: "file", Value: "deadbeef", CVE: "CVE-2024-1234"})
	_ = seedIOC(t, pool, seedOpts{Type: "domain-name", Value: "unrelated.example", CVE: "CVE-2099-0001"})

	n, err := e.ruleSharedCVE(ctx, url)
	if err != nil {
		t.Fatalf("ruleSharedCVE: %v", err)
	}
	if n != 1 {
		t.Fatalf("n = %d, want 1", n)
	}
	got := findRelationship(t, corr, url.ID, "shares-cve")
	if len(got) != 1 || got[0].OtherIOCID != file.ID {
		t.Fatalf("shares-cve = %+v, want target %s", got, file.ID)
	}
	if got[0].Confidence != 75 {
		t.Errorf("confidence = %d, want 75", got[0].Confidence)
	}
}

// TestRuleSharedCVE_Integration_NoMatch proves a unique CVE produces no
// correlation.
func TestRuleSharedCVE_Integration_NoMatch(t *testing.T) {
	pool := testDB(t)
	e, _ := newTestEngine(pool)
	ctx := context.Background()

	only := seedIOC(t, pool, seedOpts{Type: "url", Value: "http://lonely.example/poc", CVE: "CVE-2024-9999"})
	n, err := e.ruleSharedCVE(ctx, only)
	if err != nil {
		t.Fatalf("ruleSharedCVE: %v", err)
	}
	if n != 0 {
		t.Fatalf("n = %d, want 0", n)
	}
}

// TestCorrelateIOC_Integration_EndToEnd drives the full CorrelateIOC entry
// point (not the individual rule methods) so the type-switch dispatch and
// the CVE branch are covered together, matching how handlers actually call
// this package.
func TestCorrelateIOC_Integration_EndToEnd(t *testing.T) {
	pool := testDB(t)
	e, _ := newTestEngine(pool)
	ctx := context.Background()

	seedIOC(t, pool, seedOpts{Type: "domain-name", Value: "example.com"})
	newIOC := seedIOC(t, pool, seedOpts{Type: "domain-name", Value: "shop.example.com", CVE: "CVE-2024-5555"})
	seedIOC(t, pool, seedOpts{Type: "file", Value: "cafebabe", CVE: "CVE-2024-5555"})

	n, err := e.CorrelateIOC(ctx, newIOC)
	if err != nil {
		t.Fatalf("CorrelateIOC: %v", err)
	}
	// subdomain-of (example.com) + shares-cve (cafebabe) = 2.
	if n != 2 {
		t.Fatalf("n = %d, want 2", n)
	}
}

// TestCorrelateIOC_Integration_UnrecognizedTypeSkipsSwitch proves a type not
// handled by the switch (e.g. "file") still runs the duplicate + CVE rules
// but skips the type-specific branch without error.
func TestCorrelateIOC_Integration_UnrecognizedTypeSkipsSwitch(t *testing.T) {
	pool := testDB(t)
	e, _ := newTestEngine(pool)
	ctx := context.Background()

	ioc := seedIOC(t, pool, seedOpts{Type: "file", Value: "0123456789abcdef"})
	n, err := e.CorrelateIOC(ctx, ioc)
	if err != nil {
		t.Fatalf("CorrelateIOC: %v", err)
	}
	if n != 0 {
		t.Fatalf("n = %d, want 0", n)
	}
}

// TestRules_Integration_ErrorPropagation closes the pool before invoking
// each rule so every "if err != nil { return ..., err }" branch — otherwise
// unreachable against a healthy database — is exercised. Also drives
// ruleIPSameNetwork into its fallback call site via the same failure.
func TestRules_Integration_ErrorPropagation(t *testing.T) {
	pool := testDB(t)
	dsn := os.Getenv("THREATFLOW_TEST_DB_URL")

	domainIOC := seedIOC(t, pool, seedOpts{Type: "domain-name", Value: "closed.example"})
	urlIOC := seedIOC(t, pool, seedOpts{Type: "url", Value: "http://closed.example/x"})
	ipIOC := seedIOC(t, pool, seedOpts{Type: "ipv4-addr", Value: "10.0.0.1"})
	cveIOC := seedIOC(t, pool, seedOpts{Type: "file", Value: "abc", CVE: "CVE-2024-0001"})

	pool.Close()
	_ = dsn

	e, _ := newTestEngine(pool)
	ctx := context.Background()

	if _, err := e.ruleCrossFeedDuplicate(ctx, domainIOC); err == nil {
		t.Error("ruleCrossFeedDuplicate: expected error on closed pool")
	}
	if _, err := e.ruleURLResolvesToDomain(ctx, urlIOC); err == nil {
		t.Error("ruleURLResolvesToDomain: expected error on closed pool")
	}
	if _, err := e.ruleDomainSubdomain(ctx, domainIOC); err == nil {
		t.Error("ruleDomainSubdomain: expected error on closed pool")
	}
	if _, err := e.ruleIPSameNetwork(ctx, ipIOC); err == nil {
		t.Error("ruleIPSameNetwork: expected error on closed pool (via fallback)")
	}
	if _, err := e.ruleSharedCVE(ctx, cveIOC); err == nil {
		t.Error("ruleSharedCVE: expected error on closed pool")
	}

	// CorrelateIOC itself never bubbles rule errors — it logs and continues —
	// so it must still return (0, nil) even though every rule failed.
	n, err := e.CorrelateIOC(ctx, domainIOC)
	if err != nil {
		t.Fatalf("CorrelateIOC: unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("n = %d, want 0", n)
	}
}
