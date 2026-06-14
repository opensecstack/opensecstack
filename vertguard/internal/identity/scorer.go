package identity

// Scored bundles a final classification + aggregated confidence.
type Scored struct {
	Classification Classification
	Confidence     float64
}

// Score aggregates indicator hits into a final classification.
//
// Aggregation rule (mirrors prompt + phishing scorers):
//
//   1. Pick the max base confidence across matches.
//   2. Apply category boost based on the highest-severity match:
//        SANCTIONED_JURISDICTION → +0.20
//        ID_FORMAT_MISMATCH      → +0.15
//        CRED_STUFFING           → +0.15
//        REPLAY_SUSPECTED        → +0.10
//        SYNTHETIC_PROFILE       → +0.10
//        others                  → unchanged
//   3. Multi-match boost: +0.05 per additional match, capped at +0.15.
//   4. Context modifier:
//        kyc              →  0
//        login            → −0.05
//        account_recovery → +0.10
//   5. Clamp to [0, 1].
//   6. Compare against thresholds.
func Score(matches []Match, ctx Context, cleanT, blockT float64) Scored {
	if len(matches) == 0 {
		return Scored{Classification: ClassificationClean, Confidence: 0}
	}

	max := 0.0
	for _, m := range matches {
		if m.Confidence > max {
			max = m.Confidence
		}
	}
	topCat := Category("")
	for _, m := range matches {
		if m.Confidence == max {
			topCat = m.Category
			break
		}
	}
	switch topCat {
	case CategorySanctionedJurisdiction:
		max += 0.20
	case CategoryIDFormatMismatch, CategoryCredStuffing:
		max += 0.15
	case CategoryReplaySuspected, CategorySyntheticProfile:
		max += 0.10
	}

	if extra := len(matches) - 1; extra > 0 {
		boost := 0.05 * float64(extra)
		if boost > 0.15 {
			boost = 0.15
		}
		max += boost
	}

	switch ctx {
	case ContextLogin:
		max -= 0.05
	case ContextAccountRecovery:
		max += 0.10
	}

	if max < 0 {
		max = 0
	}
	if max > 1 {
		max = 1
	}

	switch {
	case max >= blockT:
		return Scored{Classification: ClassificationBlocked, Confidence: max}
	case max < cleanT:
		return Scored{Classification: ClassificationClean, Confidence: max}
	default:
		return Scored{Classification: ClassificationSuspicious, Confidence: max}
	}
}
