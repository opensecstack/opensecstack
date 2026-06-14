package phishing

// Scored bundles a final classification + aggregated confidence.
type Scored struct {
	Classification Classification
	Confidence     float64
}

// Score aggregates indicator hits into a final classification.
//
// Aggregation rule (v0.1.0-alpha.0):
//
//  1. Pick the max base confidence across matches.
//  2. Apply category boost on the top-scoring match's category:
//     URL_OBFUSCATION     → +0.10
//     BRAND_IMPERSONATION → +0.10
//     CREDENTIAL_HARVEST  → +0.15
//     URGENCY             → +0.05
//     others              → unchanged
//  3. Multi-match boost: +0.05 / additional match, capped +0.15.
//  4. Kind context: kind=="email" with a CREDENTIAL_HARVEST or
//     BRAND_IMPERSONATION match → +0.10 (mailbox is the high-value
//     target — same indicator on a free-form URL string is weaker).
//  5. Clamp to [0,1] then compare against thresholds.
func Score(matches []Match, kind Kind, cleanT, blockT float64) Scored {
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
	case CategoryURLObfuscation, CategoryBrandImpersonation:
		max += 0.10
	case CategoryCredentialHarvest:
		max += 0.15
	case CategoryUrgency:
		max += 0.05
	}

	// Multi-match boost.
	if extra := len(matches) - 1; extra > 0 {
		boost := 0.05 * float64(extra)
		if boost > 0.15 {
			boost = 0.15
		}
		max += boost
	}

	// Kind context boost — mail bodies elevate harvest+brand signals.
	if kind == KindEmail {
		for _, m := range matches {
			if m.Category == CategoryCredentialHarvest || m.Category == CategoryBrandImpersonation {
				max += 0.10
				break
			}
		}
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
