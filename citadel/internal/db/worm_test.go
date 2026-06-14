package db

import (
	"encoding/hex"
	"testing"
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
