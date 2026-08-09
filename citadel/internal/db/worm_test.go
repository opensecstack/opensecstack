package db

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// ── TripleHash unit tests (no DB required) ────────────────────────────────────

func TestTripleHash_Length(t *testing.T) {
	h := TripleHash([]byte("hello citadel"))
	// 128 bytes → 256 hex chars
	if len(h) != 256 {
		t.Errorf("expected 256 hex chars, got %d", len(h))
	}
}

func TestTripleHash_ValidHex(t *testing.T) {
	h := TripleHash([]byte("sin ecosystem"))
	if _, err := hex.DecodeString(h); err != nil {
		t.Errorf("TripleHash returned invalid hex: %v", err)
	}
}

func TestTripleHash_Deterministic(t *testing.T) {
	payload := []byte("deterministic test payload")
	h1 := TripleHash(payload)
	h2 := TripleHash(payload)
	if h1 != h2 {
		t.Error("TripleHash is not deterministic")
	}
}

func TestTripleHash_DifferentPayloads(t *testing.T) {
	h1 := TripleHash([]byte("payload A"))
	h2 := TripleHash([]byte("payload B"))
	if h1 == h2 {
		t.Error("different payloads produced the same TripleHash")
	}
}

func TestTripleHash_EmptyPayload(t *testing.T) {
	h := TripleHash([]byte{})
	if len(h) != 256 {
		t.Errorf("empty payload: expected 256 hex chars, got %d", len(h))
	}
}

// ── chainHash unit tests ─────────────────────────────────────────────────────

func TestChainHash_Genesis(t *testing.T) {
	genesis := genesisHash()
	if len(genesis) != 64 {
		t.Errorf("genesis hash: expected 64 hex chars, got %d", len(genesis))
	}
	if _, err := hex.DecodeString(genesis); err != nil {
		t.Errorf("genesis hash invalid hex: %v", err)
	}
}

func TestChainHash_Deterministic(t *testing.T) {
	prev := genesisHash()
	payload := []byte(`{"event":"test"}`)
	h1 := chainHash(prev, payload)
	h2 := chainHash(prev, payload)
	if h1 != h2 {
		t.Error("chainHash is not deterministic")
	}
}

func TestChainHash_ChangePrevBreaksChain(t *testing.T) {
	payload := []byte(`{"event":"test"}`)
	h1 := chainHash(genesisHash(), payload)
	h2 := chainHash("aaaa"+genesisHash()[4:], payload)
	if h1 == h2 {
		t.Error("different prev hashes should produce different chain hashes")
	}
}

func TestChainHash_ChangePayloadBreaksChain(t *testing.T) {
	prev := genesisHash()
	h1 := chainHash(prev, []byte(`{"event":"original"}`))
	h2 := chainHash(prev, []byte(`{"event":"tampered"}`))
	if h1 == h2 {
		t.Error("different payloads should produce different chain hashes")
	}
}

func TestChainHash_InvalidHexPrevHashFallsBackToRawBytes(t *testing.T) {
	// "not-valid-hex" cannot be hex-decoded — chainHash must fall back to
	// treating it as raw bytes rather than erroring, and that fallback must
	// still be deterministic.
	payload := []byte(`{"event":"test"}`)
	h1 := chainHash("not-valid-hex", payload)
	h2 := chainHash("not-valid-hex", payload)
	if h1 != h2 {
		t.Error("chainHash fallback for invalid hex prevHash is not deterministic")
	}
	if len(h1) != 64 {
		t.Errorf("expected 64 hex chars, got %d", len(h1))
	}
	// Must differ from the result of hashing a validly-hex-decoded prevHash
	// of different content, confirming the raw-bytes fallback actually
	// participates in the hash (not silently ignored/zeroed).
	hValidHex := chainHash(genesisHash(), payload)
	if h1 == hValidHex {
		t.Error("invalid-hex fallback produced the same hash as a genuinely different prevHash")
	}
}

// ── nullIfEmpty unit tests ────────────────────────────────────────────────────

func TestNullIfEmpty_EmptyStringReturnsNil(t *testing.T) {
	if got := nullIfEmpty(""); got != nil {
		t.Errorf("nullIfEmpty(\"\") = %v, want nil", got)
	}
}

func TestNullIfEmpty_NonEmptyStringReturnsItself(t *testing.T) {
	got := nullIfEmpty("abc123")
	s, ok := got.(string)
	if !ok {
		t.Fatalf("nullIfEmpty(\"abc123\") returned %T, want string", got)
	}
	if s != "abc123" {
		t.Errorf("nullIfEmpty(\"abc123\") = %q, want %q", s, "abc123")
	}
}

// ── AppendWORM / VerifyChain / GetLastChainHash error paths (no live DB) ──────

// TestAppendWORM_BeginTxErrorIsWrapped confirms AppendWORM propagates a real
// transaction-begin failure (DB unreachable) instead of silently returning a
// zero-value entry — a WORM append that "succeeds" without actually writing
// would be a silent audit-trail gap, exactly what the WORM chain exists to
// prevent.
func TestAppendWORM_BeginTxErrorIsWrapped(t *testing.T) {
	d := unreachableDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	entry, err := d.AppendWORM(ctx, "test-source", "test.event", "proj-1", []byte(`{}`), "", "")
	if err == nil {
		t.Fatal("expected error appending to WORM against an unreachable database")
	}
	if entry != nil {
		t.Errorf("expected nil entry on error, got %+v", entry)
	}
	if !strings.Contains(err.Error(), "worm: begin tx:") {
		t.Errorf("expected wrapped 'worm: begin tx:' error, got: %v", err)
	}
}

// TestVerifyChain_QueryErrorIsWrapped confirms VerifyChain propagates a real
// query failure rather than reporting an empty-but-"Valid: true" result,
// which would be a false assurance that the audit chain is intact.
func TestVerifyChain_QueryErrorIsWrapped(t *testing.T) {
	d := unreachableDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	from := time.Now().UTC().Add(-time.Hour)
	to := time.Now().UTC()

	result, err := d.VerifyChain(ctx, from, to)
	if err == nil {
		t.Fatal("expected error verifying chain against an unreachable database")
	}
	if result != nil {
		t.Errorf("expected nil result on error, got %+v", result)
	}
	if !strings.Contains(err.Error(), "worm: verify query:") {
		t.Errorf("expected wrapped 'worm: verify query:' error, got: %v", err)
	}
}

// TestGetLastChainHash_QueryErrorIsNotConflatedWithGenesis confirms a real
// query failure surfaces as an error rather than being disguised as "empty
// chain, use genesis" — silently anchoring a new entry on a fabricated
// genesis hash during an outage would corrupt chain continuity instead of
// failing loudly.
func TestGetLastChainHash_QueryErrorIsNotConflatedWithGenesis(t *testing.T) {
	d := unreachableDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hash, err := d.GetLastChainHash(ctx)
	if err == nil {
		t.Fatal("expected error for a real query failure, got nil")
	}
	if hash != "" {
		t.Errorf("expected empty hash on error, got %q", hash)
	}
	if !strings.Contains(err.Error(), "db: GetLastChainHash: query:") {
		t.Errorf("expected wrapped 'db: GetLastChainHash: query:' error, got: %v", err)
	}
}

// ── Benchmark (no DB) ─────────────────────────────────────────────────────────

func BenchmarkTripleHash_1KB(b *testing.B) {
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = 0xAB
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = TripleHash(payload)
	}
}

func BenchmarkChainHash(b *testing.B) {
	prev := genesisHash()
	payload := []byte(`{"id":"bench","event":"scan.created","timestamp":"2026-04-05T00:00:00Z"}`)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		prev = chainHash(prev, payload)
	}
}
