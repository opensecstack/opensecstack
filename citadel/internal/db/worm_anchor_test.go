//go:build integration

// These tests need a real, migrated `worm_entries`/`anchors` schema, which
// only exists in the citadel_worm_test database the test-citadel-worm CI job
// migrates (see .github/workflows/ci.yml) — the plain test-citadel job's
// Postgres service is deliberately left unmigrated, and every existing test
// in this package was written around that constraint (they only exercise
// error paths on closed/invalid connections, never a real table). Confirmed
// the hard way: without this build tag, these tests ran as part of plain
// `go test ./...` in test-citadel and failed with
// `relation "worm_entries" does not exist` in actual CI, despite passing
// locally where migrations were applied manually first.

package db

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ── Live-Postgres anchor tests ────────────────────────────────────────────
//
// These exercise ConfigureAnchoring + the anchor-production hook in
// AppendWORM and the anchor-verification pass in VerifyChain against a
// real database — pure hashing/error-path behavior is already covered
// without a DB in worm_test.go. Following the same convention as
// internal/api/handlers/worm_integration_test.go: read the connection
// string from an env var and skip (not fail) when it's unset, rather than
// assuming a build tag. Unlike worm_integration_test.go (which requires
// `-tags integration`, a tag the real root .github/workflows/ci.yml's
// test-citadel job never passes — its "Run tests" step runs plain
// `go test ./... -coverprofile=... -covermode=atomic`, so that file's
// tests never execute in CI at all today, a separate pre-existing gap),
// these tests carry NO build tag and read DATABASE_URL — the exact env
// var that job's "Run tests" step actually sets — so they run as part of
// the plain `go test ./...` CI already invokes.
//
// Note: citadel/.github/workflows/ci.yml (nested under this platform's own
// directory) is a stale, non-executing file — GitHub Actions only
// discovers workflows under the repo-root .github/workflows/, never in a
// subdirectory. It sets CITADEL_DB_URL, which looks authoritative but
// isn't; the root workflow (the one that actually runs) sets DATABASE_URL
// for this job. Confirmed directly against the root file, not this one.

// anchorTestDB opens a real DB connection or skips if DATABASE_URL is
// unset. Each caller gets a fresh connection so tests can run with
// t.Parallel() without sharing a pool, and the pool is closed on cleanup.
func anchorTestDB(t *testing.T) *DB {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set — skipping live-Postgres anchor test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(context.Background()); err != nil {
		t.Fatalf("ping test database: %v", err)
	}
	return &DB{Pool: pool}
}

// testKeyHex generates a fresh Ed25519 keypair for a test and returns the
// hex-encoded private key (the CITADEL_MASTER_KEY format, matching
// keygen.go's convention) plus the raw key pair for direct use (e.g. to
// forge a wrong-key signature).
func testKeyHex(t *testing.T) (hexKey string, priv ed25519.PrivateKey, pub ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return hex.EncodeToString(priv), priv, pub
}

// uniqueSource returns a project/source string unique to this test run so
// concurrent/previous test data never pollutes sequence-range queries —
// worm_entries.sequence_num is a single global counter, but VerifyChain
// filters by ts_utc, and each test scopes [from, to] tightly around its own
// inserts.
func uniqueSource(t *testing.T) string {
	t.Helper()
	return "anchor-test-" + t.Name() + "-" + time.Now().UTC().Format("150405.000000000")
}

// TestAppendWORM_AnchorCreatedExactlyAtInterval confirms an anchor row is
// inserted only on the Nth, 2Nth, ... entry (never before or after), for a
// small interval that's easy to assert exhaustively.
func TestAppendWORM_AnchorCreatedExactlyAtInterval(t *testing.T) {
	d := anchorTestDB(t)
	hexKey, _, _ := testKeyHex(t)
	if err := d.ConfigureAnchoring(hexKey, 3); err != nil {
		t.Fatalf("ConfigureAnchoring: %v", err)
	}
	ctx := context.Background()
	source := uniqueSource(t)

	var seqNums []int64
	for i := 0; i < 7; i++ {
		entry, err := d.AppendWORM(ctx, source, "test.anchor_interval", "proj-anchor", []byte(`{}`), "", "")
		if err != nil {
			t.Fatalf("AppendWORM[%d]: %v", i, err)
		}
		seqNums = append(seqNums, entry.SequenceNum)
	}

	for _, seq := range seqNums {
		var count int
		if err := d.Pool.QueryRow(ctx, `SELECT count(*) FROM anchors WHERE sequence_num = $1`, seq).Scan(&count); err != nil {
			t.Fatalf("count anchors for sequence_num=%d: %v", seq, err)
		}
		wantAnchor := seq%3 == 0
		gotAnchor := count == 1
		if gotAnchor != wantAnchor {
			t.Errorf("sequence_num=%d: anchor present=%v, want %v", seq, gotAnchor, wantAnchor)
		}
		if count > 1 {
			t.Errorf("sequence_num=%d: expected at most 1 anchor row, got %d", seq, count)
		}
	}
}

// TestAppendWORM_AnchorSignatureVerifiesAgainstRealKey confirms the anchor
// signature produced by AppendWORM is a genuine Ed25519 signature over the
// chain_hash, verifiable with the corresponding public key.
func TestAppendWORM_AnchorSignatureVerifiesAgainstRealKey(t *testing.T) {
	d := anchorTestDB(t)
	hexKey, _, pub := testKeyHex(t)
	if err := d.ConfigureAnchoring(hexKey, 1); err != nil {
		t.Fatalf("ConfigureAnchoring: %v", err)
	}
	ctx := context.Background()
	source := uniqueSource(t)

	entry, err := d.AppendWORM(ctx, source, "test.anchor_sig", "proj-anchor", []byte(`{"x":1}`), "", "")
	if err != nil {
		t.Fatalf("AppendWORM: %v", err)
	}

	var chainHashInAnchor, sigHex string
	err = d.Pool.QueryRow(ctx,
		`SELECT chain_hash, ed25519_sig FROM anchors WHERE sequence_num = $1`, entry.SequenceNum,
	).Scan(&chainHashInAnchor, &sigHex)
	if err != nil {
		t.Fatalf("expected an anchor row for sequence_num=%d: %v", entry.SequenceNum, err)
	}
	if chainHashInAnchor != entry.ChainHash {
		t.Fatalf("anchor chain_hash = %q, want %q", chainHashInAnchor, entry.ChainHash)
	}

	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatalf("anchor ed25519_sig is not valid hex: %v", err)
	}
	if !ed25519.Verify(pub, []byte(chainHashInAnchor), sig) {
		t.Fatal("anchor signature does not verify against the public key derived from the configured master key")
	}
}

// TestVerifyChain_AnchorTamperedChainHashIsCaught confirms VerifyChain
// reports a break when an anchor row's chain_hash is tampered with directly
// in the database — the anchor's claimed chain_hash then disagrees with
// the real chain_hash at that sequence_num in worm_entries, which must be
// treated with the same severity as a chain_hash break.
func TestVerifyChain_AnchorTamperedChainHashIsCaught(t *testing.T) {
	d := anchorTestDB(t)
	hexKey, _, _ := testKeyHex(t)
	if err := d.ConfigureAnchoring(hexKey, 1); err != nil {
		t.Fatalf("ConfigureAnchoring: %v", err)
	}
	ctx := context.Background()
	source := uniqueSource(t)

	// Bracket the verification window tightly around this test's own
	// inserts (not a wide +/-1 minute buffer) — the anchors table is not
	// WORM-protected, so other tests in this shared, stateful test
	// database may tamper their own anchor rows and never revert them; a
	// wide window would pick up that unrelated tampering and make this
	// test's "before tampering" sanity check spuriously fail.
	from := time.Now().UTC()
	entry, err := d.AppendWORM(ctx, source, "test.anchor_tamper_hash", "proj-anchor", []byte(`{}`), "", "")
	if err != nil {
		t.Fatalf("AppendWORM: %v", err)
	}
	to := time.Now().UTC()

	// Sanity: chain is valid and anchor-verified before tampering.
	before, err := d.VerifyChain(ctx, from, to)
	if err != nil {
		t.Fatalf("VerifyChain (before): %v", err)
	}
	if !before.Valid || !before.AnchorVerified {
		t.Fatalf("expected Valid=true AnchorVerified=true before tampering, got %+v", before)
	}

	var originalHash string
	if err := d.Pool.QueryRow(ctx, `SELECT chain_hash FROM anchors WHERE sequence_num = $1`, entry.SequenceNum).Scan(&originalHash); err != nil {
		t.Fatalf("read original anchor chain_hash: %v", err)
	}
	t.Cleanup(func() {
		// Restore the row so later tests sharing this database aren't
		// affected by this test's tampering (anchors carries no
		// append-only protection, unlike worm_entries).
		_, _ = d.Pool.Exec(context.Background(), `UPDATE anchors SET chain_hash = $1 WHERE sequence_num = $2`, originalHash, entry.SequenceNum)
	})

	tamperedHash := "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	tag, err := d.Pool.Exec(ctx, `UPDATE anchors SET chain_hash = $1 WHERE sequence_num = $2`, tamperedHash, entry.SequenceNum)
	if err != nil {
		t.Fatalf("tamper anchor chain_hash: %v", err)
	}
	if tag.RowsAffected() != 1 {
		t.Fatalf("expected to tamper exactly 1 anchor row, affected %d", tag.RowsAffected())
	}

	after, err := d.VerifyChain(ctx, from, to)
	if err != nil {
		t.Fatalf("VerifyChain (after): %v", err)
	}
	if after.Valid {
		t.Fatal("expected VerifyChain to report a break after tampering with the anchor's chain_hash")
	}
	if after.AnchorVerified {
		t.Error("expected AnchorVerified=false after tampering with the anchor's chain_hash")
	}
	if after.BreakAt == "" {
		t.Error("expected BreakAt to be populated after tampering with the anchor's chain_hash")
	}
}

// TestVerifyChain_AnchorTamperedSignatureIsCaught confirms VerifyChain
// reports a break when an anchor row's ed25519_sig is replaced with a
// well-formed but wrong signature (i.e. it doesn't verify against the
// anchor's own claimed chain_hash), independent of the chain_hash-match
// check.
func TestVerifyChain_AnchorTamperedSignatureIsCaught(t *testing.T) {
	d := anchorTestDB(t)
	hexKey, priv, _ := testKeyHex(t)
	if err := d.ConfigureAnchoring(hexKey, 1); err != nil {
		t.Fatalf("ConfigureAnchoring: %v", err)
	}
	ctx := context.Background()
	source := uniqueSource(t)

	from := time.Now().UTC()
	entry, err := d.AppendWORM(ctx, source, "test.anchor_tamper_sig", "proj-anchor", []byte(`{}`), "", "")
	if err != nil {
		t.Fatalf("AppendWORM: %v", err)
	}
	to := time.Now().UTC()

	// A validly-formed signature, but over the wrong message — verifies
	// fine as a signature in general, just not against this chain_hash.
	wrongSig := ed25519.Sign(priv, []byte("not-the-real-chain-hash"))
	wrongSigHex := hex.EncodeToString(wrongSig)

	tag, err := d.Pool.Exec(ctx, `UPDATE anchors SET ed25519_sig = $1 WHERE sequence_num = $2`, wrongSigHex, entry.SequenceNum)
	if err != nil {
		t.Fatalf("tamper anchor ed25519_sig: %v", err)
	}
	if tag.RowsAffected() != 1 {
		t.Fatalf("expected to tamper exactly 1 anchor row, affected %d", tag.RowsAffected())
	}

	after, err := d.VerifyChain(ctx, from, to)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if after.Valid {
		t.Fatal("expected VerifyChain to report a break after tampering with the anchor's signature")
	}
	if after.AnchorVerified {
		t.Error("expected AnchorVerified=false after tampering with the anchor's signature")
	}
	if after.BreakAt == "" {
		t.Error("expected BreakAt to be populated after tampering with the anchor's signature")
	}
}

// TestAppendWORM_AnchoringDisabledDoesNotBreakAppend confirms that with no
// master key configured (the documented "anchoring disabled" state —
// config.WarnIfInsecure warns but does not fail), normal appends still
// succeed and simply produce no anchor rows, even across an anchor
// interval boundary.
func TestAppendWORM_AnchoringDisabledDoesNotBreakAppend(t *testing.T) {
	d := anchorTestDB(t)
	if err := d.ConfigureAnchoring("", 2); err != nil {
		t.Fatalf("ConfigureAnchoring: %v", err)
	}
	ctx := context.Background()
	source := uniqueSource(t)

	var lastSeq int64
	for i := 0; i < 3; i++ {
		entry, err := d.AppendWORM(ctx, source, "test.anchor_disabled", "proj-anchor", []byte(`{}`), "", "")
		if err != nil {
			t.Fatalf("AppendWORM[%d]: %v", i, err)
		}
		lastSeq = entry.SequenceNum
	}

	var count int
	if err := d.Pool.QueryRow(ctx, `SELECT count(*) FROM anchors WHERE sequence_num <= $1 AND sequence_num > $1 - 3`, lastSeq).Scan(&count); err != nil {
		t.Fatalf("count anchors: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 anchors with anchoring disabled, got %d", count)
	}
}

// TestVerifyChain_ZeroAnchorsInRangeReportsAnchorVerifiedTrue confirms that
// when a verified range genuinely contains no anchors (window narrower
// than the anchor interval), AnchorVerified is true — "nothing to check"
// must not be reported as a false negative.
func TestVerifyChain_ZeroAnchorsInRangeReportsAnchorVerifiedTrue(t *testing.T) {
	d := anchorTestDB(t)
	hexKey, _, _ := testKeyHex(t)
	// Large interval relative to the handful of entries below — guarantees
	// no anchor boundary is crossed in this test.
	if err := d.ConfigureAnchoring(hexKey, 1000); err != nil {
		t.Fatalf("ConfigureAnchoring: %v", err)
	}
	ctx := context.Background()
	source := uniqueSource(t)

	from := time.Now().UTC()
	for i := 0; i < 3; i++ {
		if _, err := d.AppendWORM(ctx, source, "test.anchor_zero_range", "proj-anchor", []byte(`{}`), "", ""); err != nil {
			t.Fatalf("AppendWORM[%d]: %v", i, err)
		}
	}
	to := time.Now().UTC()

	result, err := d.VerifyChain(ctx, from, to)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !result.Valid {
		t.Fatalf("expected Valid=true, got break at %q", result.BreakAt)
	}
	if !result.AnchorVerified {
		t.Error("expected AnchorVerified=true for a range with zero anchors, got false")
	}
}

// TestConfigureAnchoring_RejectsMalformedMasterKey confirms a non-empty but
// malformed CITADEL_MASTER_KEY is a hard configuration error (matching
// cmd/citadel/main.go's log.Fatalf on this path) rather than silently
// falling back to "anchoring disabled" — a config typo must be loud, not a
// silent security downgrade.
func TestConfigureAnchoring_RejectsMalformedMasterKey(t *testing.T) {
	d := &DB{}
	if err := d.ConfigureAnchoring("not-valid-hex-zzz", 100); err == nil {
		t.Error("expected error for non-hex master key, got nil")
	}
	if err := d.ConfigureAnchoring("abcd", 100); err == nil {
		t.Error("expected error for wrong-length master key, got nil")
	}
}
