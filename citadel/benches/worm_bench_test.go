//go:build bench

package benches

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/opensecstack/citadel/internal/db"
)

// BenchmarkTripleHash measures TripleHash computation for the IEEE paper Table II.
func BenchmarkTripleHash_100B(b *testing.B) {
	payload := make([]byte, 100)
	for i := range payload {
		payload[i] = 0xAB
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = db.TripleHash(payload)
	}
}

func BenchmarkTripleHash_1KB(b *testing.B) {
	payload := make([]byte, 1024)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = db.TripleHash(payload)
	}
}

// BenchmarkWORM_ChainStep measures the cost of a single WORM chain hash step:
// SHA-256(prev_hash || payload) — the per-entry cost in chain construction.
func BenchmarkWORM_ChainStep(b *testing.B) {
	b.ReportAllocs()
	prevHash := make([]byte, 32)
	payload := []byte(`{"id":"bench","event":"scan.created","ts":"2026-04-05T00:00:00Z","source":"apiguard"}`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := sha256.New()
		h.Write(prevHash)
		h.Write(payload)
		prevHash = h.Sum(prevHash[:0])
	}
}

// BenchmarkWORM_FullEntry measures the full WORM entry preparation:
// TripleHash + chain_hash (no DB write — pure compute cost).
func BenchmarkWORM_FullEntry(b *testing.B) {
	b.ReportAllocs()
	prevHashHex := hex.EncodeToString(make([]byte, 32))
	payload := []byte(`{"id":"bench","event":"scan.created","actor":"user_42","ts":"2026-04-05T00:00:00Z"}`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		th := db.TripleHash(payload)
		prev, _ := hex.DecodeString(prevHashHex)
		h := sha256.New()
		h.Write(prev)
		h.Write(payload)
		prevHashHex = hex.EncodeToString(h.Sum(nil))
		_ = th
	}
}
