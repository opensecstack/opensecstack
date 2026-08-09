//go:build bench

package benches

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/opensecstack/citadel/internal/marshal"
)

// ── Mock Store + TokenVerifier (inline — no import of test package) ──────────

const (
	benchOperatorUserID = "1"
	benchVerifierUserID = "2"
	benchOperatorToken  = "bench-actor-token"
	benchVerifierToken  = "bench-verifier-token"
)

var (
	benchOperatorPub, benchOperatorPriv, _ = ed25519.GenerateKey(nil)
	benchVerifierPub, benchVerifierPriv, _ = ed25519.GenerateKey(nil)
)

type benchStore struct{}

func (benchStore) ActionCount(_ context.Context, _ string, _ time.Duration) (int, error) {
	return 0, nil
}

func (benchStore) AppendWORM(_ context.Context, _, _, _ string, _ []byte, sigOperator, sigVerifier string) (*marshal.WORMEntry, error) {
	return &marshal.WORMEntry{
		ID:          uuid.New(),
		SequenceNum: 1,
		ChainHash:   "bench_chain_hash",
		SigOperator: sigOperator,
		SigVerifier: sigVerifier,
	}, nil
}

func (benchStore) GetSigningKey(_ context.Context, userID string) (ed25519.PublicKey, bool, error) {
	switch userID {
	case benchOperatorUserID:
		return benchOperatorPub, true, nil
	case benchVerifierUserID:
		return benchVerifierPub, true, nil
	}
	return nil, false, nil
}

type benchTokenVerifier struct{}

func (benchTokenVerifier) Verify(_ context.Context, token string) (string, string, error) {
	switch token {
	case benchOperatorToken:
		return benchOperatorUserID, "operator", nil
	case benchVerifierToken:
		return benchVerifierUserID, "analyst", nil
	}
	return "", "", errors.New("benchTokenVerifier: unknown token")
}

func baseKerkese() *marshal.Kerkese {
	return &marshal.Kerkese{
		KerkeseVersion: "1.0",
		TsUTC:          time.Date(2026, 4, 5, 10, 0, 0, 0, time.UTC),
		ProjectID:      "bench",
		ExecutionID:    uuid.New(),
		Action: marshal.KerkeseAction{
			Type:        "API_SCAN_INITIATE",
			Description: "benchmark scan",
		},
		Actor:         marshal.KerkeseActor{UserID: benchOperatorUserID, Role: "operator"},
		Verifier:      marshal.KerkeseVerifier{UserID: benchVerifierUserID, Role: "analyst"},
		SoD:           marshal.KerkeseSoD{OperatorUserID: benchOperatorUserID, VerifierUserID: benchVerifierUserID},
		ActorToken:    benchOperatorToken,
		VerifierToken: benchVerifierToken,
	}
}

// signBenchKerkese signs k with the fixed benchmark operator/verifier keys —
// mirrors sdk/go/citadel.Sign / marshal.CanonicalPayload.
func signBenchKerkese(k *marshal.Kerkese) {
	payload := []byte(marshal.CanonicalPayload(*k))
	k.SigOperator = hex.EncodeToString(ed25519.Sign(benchOperatorPriv, payload))
	k.SigVerifier = hex.EncodeToString(ed25519.Sign(benchVerifierPriv, payload))
}

// BenchmarkMARSHAL_Evaluate measures the full 5-gate evaluation latency,
// including sinauth token verification (Gate 1/Gate 3 AuthN) and Ed25519
// Operator/Verifier signature verification, with signature enforcement ON —
// this is the number that belongs in the IEEE paper's Table II "MARSHAL
// full evaluation" row as of adrs/004-operator-verifier-ed25519-signatures.md
// and adrs/005-sinauth-identity-bridge.md.
func BenchmarkMARSHAL_Evaluate(b *testing.B) {
	engine := marshal.New(benchStore{}, benchTokenVerifier{}).EnforceSignatures(true)
	ctx := context.Background()
	k := baseKerkese()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		k.ExecutionID = uuid.New()
		signBenchKerkese(k)
		_, _ = engine.Evaluate(ctx, k)
	}
}

// BenchmarkMARSHAL_Evaluate_Unsigned measures the same path with signature
// enforcement OFF (soft mode), for comparison against the pre-signature
// baseline reported before this change.
func BenchmarkMARSHAL_Evaluate_Unsigned(b *testing.B) {
	engine := marshal.New(benchStore{}, benchTokenVerifier{})
	ctx := context.Background()
	k := baseKerkese()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		k.ExecutionID = uuid.New()
		_, _ = engine.Evaluate(ctx, k)
	}
}

// BenchmarkMARSHAL_Evaluate_Refuse measures latency when Gate 1 fails.
func BenchmarkMARSHAL_Evaluate_Refuse(b *testing.B) {
	engine := marshal.New(benchStore{}, benchTokenVerifier{}).EnforceSignatures(true)
	ctx := context.Background()
	k := baseKerkese()
	k.Actor.UserID = "999" // no matching token → Gate 1 FAIL
	k.ActorToken = "bogus"
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		k.ExecutionID = uuid.New()
		_, _ = engine.Evaluate(ctx, k)
	}
}

// BenchmarkMARSHAL_Evaluate_HardStop measures latency on NDS HARD_STOP.
func BenchmarkMARSHAL_Evaluate_HardStop(b *testing.B) {
	engine := marshal.New(benchStore{}, benchTokenVerifier{}).EnforceSignatures(true)
	ctx := context.Background()
	k := baseKerkese()
	k.SoD.VerifierUserID = k.SoD.OperatorUserID // same identity → Gate 3 HARD_STOP
	k.Verifier.UserID = k.Actor.UserID
	k.VerifierToken = benchOperatorToken
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		k.ExecutionID = uuid.New()
		signBenchKerkese(k)
		_, _ = engine.Evaluate(ctx, k)
	}
}
