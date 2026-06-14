package identity

import "testing"

func TestScore_NoMatchesIsClean(t *testing.T) {
	s := Score(nil, ContextKYC, 0.30, 0.70)
	if s.Classification != ClassificationClean || s.Confidence != 0 {
		t.Fatalf("got %+v, want clean@0", s)
	}
}

func TestScore_SanctionedBoost(t *testing.T) {
	matches := []Match{{
		Category:   CategorySanctionedJurisdiction,
		Confidence: 0.65, // base would be SUSPICIOUS, +0.20 boost → BLOCKED
	}}
	s := Score(matches, ContextKYC, 0.30, 0.70)
	if s.Classification != ClassificationBlocked {
		t.Fatalf("got %s, want BLOCKED (conf=%.3f)", s.Classification, s.Confidence)
	}
}

func TestScore_LoginContextDownweight(t *testing.T) {
	matches := []Match{{Category: CategoryEmailDisposable, Confidence: 0.32}}
	s := Score(matches, ContextLogin, 0.30, 0.70)
	// 0.32 - 0.05 = 0.27 → CLEAN
	if s.Classification != ClassificationClean {
		t.Fatalf("got %s@%.3f, want CLEAN with login downweight", s.Classification, s.Confidence)
	}
}

func TestScore_AccountRecoveryBoost(t *testing.T) {
	matches := []Match{{Category: CategoryEmailDisposable, Confidence: 0.25}}
	s := Score(matches, ContextAccountRecovery, 0.30, 0.70)
	// 0.25 + 0.10 = 0.35 → SUSPICIOUS
	if s.Classification != ClassificationSuspicious {
		t.Fatalf("got %s@%.3f, want SUSPICIOUS with account_recovery boost", s.Classification, s.Confidence)
	}
}

func TestScore_MultiMatchBoostCapped(t *testing.T) {
	matches := []Match{
		{Category: CategoryEmailDisposable, Confidence: 0.40},
		{Category: CategoryEmailDisposable, Confidence: 0.30},
		{Category: CategoryEmailDisposable, Confidence: 0.30},
		{Category: CategoryEmailDisposable, Confidence: 0.30},
		{Category: CategoryEmailDisposable, Confidence: 0.30},
	}
	s := Score(matches, ContextKYC, 0.30, 0.70)
	// max=0.40, +4 extras × 0.05 = 0.20, capped at 0.15 → 0.55 SUSPICIOUS
	if s.Classification != ClassificationSuspicious {
		t.Fatalf("got %s@%.3f", s.Classification, s.Confidence)
	}
	if s.Confidence > 0.56 {
		t.Fatalf("multi-match boost exceeded cap: %.3f", s.Confidence)
	}
}

func TestScore_Clamp(t *testing.T) {
	matches := []Match{{Category: CategorySanctionedJurisdiction, Confidence: 0.95}}
	s := Score(matches, ContextAccountRecovery, 0.30, 0.70)
	// 0.95 + 0.20 + 0.10 = 1.25, must clamp to 1.0
	if s.Confidence > 1.0 {
		t.Fatalf("confidence not clamped: %.3f", s.Confidence)
	}
}

func TestScore_BlockedBaselinePassThrough(t *testing.T) {
	matches := []Match{{Category: CategoryCredStuffing, Confidence: 0.85}}
	s := Score(matches, ContextLogin, 0.30, 0.70)
	if s.Classification != ClassificationBlocked {
		t.Fatalf("got %s@%.3f, want BLOCKED", s.Classification, s.Confidence)
	}
}
