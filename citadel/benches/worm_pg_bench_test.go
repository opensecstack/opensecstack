//go:build bench

package benches

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/opensecstack/citadel/internal/db"
)

// pgDB opens a real DB connection or skips the benchmark if CITADEL_DB_URL is unset.
func pgDB(b *testing.B) *db.DB {
	b.Helper()
	dsn := os.Getenv("CITADEL_DB_URL")
	if dsn == "" {
		b.Skip("CITADEL_DB_URL not set — skipping PostgreSQL benchmark")
	}
	d, err := db.New(context.Background(), dsn)
	if err != nil {
		b.Fatalf("pgDB: connect: %v", err)
	}
	b.Cleanup(func() { d.Close() })
	return d
}

// BenchmarkWORM_AppendSync measures the full synchronous AppendWORM latency
// including: EXCLUSIVE LOCK, prev-hash query, TripleHash, chainHash, INSERT, COMMIT.
// This produces the "WORM append (sync, PostgreSQL)" row in IEEE paper Table II.
func BenchmarkWORM_AppendSync(b *testing.B) {
	d := pgDB(b)
	ctx := context.Background()
	payload := []byte(`{"benchmark":true,"source":"worm_pg_bench","event":"bench.append"}`)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := d.AppendWORM(ctx, "bench", "bench.append", "bench-pg", payload)
		if err != nil {
			b.Fatalf("AppendWORM: %v", err)
		}
	}
}

// BenchmarkWORM_VerifyChain_1000 measures chain verification latency over 1,000 entries.
// Setup inserts exactly 1,000 entries scoped to a unique project_id, then benchmarks
// VerifyChain(from, to) — which reads, recomputes TripleHash + chainHash for all 1,000 rows.
// This produces the "Chain verification (1,000 entries)" row in IEEE paper Table II.
func BenchmarkWORM_VerifyChain_1000(b *testing.B) {
	d := pgDB(b)
	ctx := context.Background()

	// ── Setup: insert 1,000 entries ─────────────────────────────────────────
	const n = 1000
	start := time.Now().UTC().Add(-time.Millisecond) // just before inserts

	for i := 0; i < n; i++ {
		payload := []byte(fmt.Sprintf(
			`{"benchmark":true,"seq":%d,"source":"verify_bench"}`, i,
		))
		if _, err := d.AppendWORM(ctx, "bench", "bench.verify_setup", "bench-verify", payload); err != nil {
			b.Fatalf("setup AppendWORM[%d]: %v", i, err)
		}
	}

	end := time.Now().UTC().Add(time.Millisecond) // just after inserts
	b.Logf("inserted %d entries in %s", n, time.Since(start).Round(time.Millisecond))

	// ── Benchmark: verify those 1,000 entries ────────────────────────────────
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		result, err := d.VerifyChain(ctx, start, end)
		if err != nil {
			b.Fatalf("VerifyChain: %v", err)
		}
		if !result.Valid {
			b.Fatalf("chain broken at: %s", result.BreakAt)
		}
		_ = result
	}
}
