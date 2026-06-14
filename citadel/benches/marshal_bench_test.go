//go:build bench

package benches

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/opensecstack/citadel/internal/marshal"
)

// ── Mock Store (inline — no import of test package) ──────────────────────────

type benchStore struct{}

func (benchStore) SessionExists(_ context.Context, userID int64) (string, string, bool, error) {
	switch userID {
	case 1:
		return "operator", "privileged", true, nil
	case 2:
		return "analyst", "standard", true, nil
	}
	return "", "", false, nil
}

func (benchStore) ActionCount(_ context.Context, _ int64, _ time.Duration) (int, error) {
	return 0, nil
}

func (benchStore) AppendWORM(_ context.Context, _, _, _ string, _ []byte) (*marshal.WORMEntry, error) {
	return &marshal.WORMEntry{
		ID:          uuid.New(),
		SequenceNum: 1,
		ChainHash:   "bench_chain_hash",
	}, nil
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
		Actor:    marshal.KerkeseActor{UserID: 1, Role: "operator"},
		Verifier: marshal.KerkeseVerifier{UserID: 2, Role: "analyst"},
		SoD:      marshal.KerkeseSoD{OperatorUserID: 1, VerifierUserID: 2},
	}
}

// BenchmarkMARSHAL_Evaluate measures the full 5-gate evaluation latency.
// This produces the "MARSHAL full evaluation" row in IEEE paper Table II.
func BenchmarkMARSHAL_Evaluate(b *testing.B) {
	engine := marshal.New(benchStore{})
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
	engine := marshal.New(benchStore{})
	ctx := context.Background()
	k := baseKerkese()
	k.Actor.UserID = 999 // no session → Gate 1 FAIL
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		k.ExecutionID = uuid.New()
		_, _ = engine.Evaluate(ctx, k)
	}
}

// BenchmarkMARSHAL_Evaluate_HardStop measures latency on NDS HARD_STOP.
func BenchmarkMARSHAL_Evaluate_HardStop(b *testing.B) {
	engine := marshal.New(benchStore{})
	ctx := context.Background()
	k := baseKerkese()
	k.SoD.VerifierUserID = k.SoD.OperatorUserID // same identity → Gate 3 HARD_STOP
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		k.ExecutionID = uuid.New()
		_, _ = engine.Evaluate(ctx, k)
	}
}
