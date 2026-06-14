package prompt

// Scored bundles a final classification + aggregated confidence.
type Scored struct {
	Classification Classification
	Confidence     float64
}

// ValidContexts is the closed set of context-tag strings the scorer
// recognises. The handler validates req.Context against this set and
// rejects unknown values with HTTP 400 — silently defaulting unknown
// strings would mask client bugs and produce misleading audit trails.
//
// Keep in sync with the switch in Score below.
var ValidContexts = map[string]struct{}{
	"user_chat_input":            {},
	"authenticated_operator":     {},
	"internal_dev_tool":          {},
	"untrusted_third_party":      {},
	"untrusted_document_content": {},
}

// IsValidContext reports whether ctx is one of the recognised context
// tags. The empty string is NOT valid here — callers that want the
// default ("user_chat_input") must apply it before checking.
func IsValidContext(ctx string) bool {
	_, ok := ValidContexts[ctx]
	return ok
}

// Score aggregates a set of matches into a final classification,
// applying category boosts, multi-match boosts, and context adjustments.
//
// Aggregation rule (v0.1.0-alpha.0):
//
//   1. Pick the max base confidence across matches.
//   2. Apply category boost:
//        LLM01 → +0.10  (prompt injection is highest-priority)
//        LLM06 → +0.05  (sensitive info disclosure)
//        others → unchanged
//   3. Apply multi-match boost: +0.05 per additional match, capped +0.15.
//   4. Apply context adjustment (see below).
//   5. Clamp to [0, 1].
//   6. Compare against thresholds to classify.
//
// Context map:
//
//   authenticated_operator      → −0.10
//   internal_dev_tool           → −0.20
//   user_chat_input (default)   →   0
//   untrusted_third_party       → +0.10
//   untrusted_document_content  → +0.20
func Score(matches []Match, context string, cleanT, blockT float64) Scored {
	if len(matches) == 0 {
		return Scored{Classification: ClassificationClean, Confidence: 0}
	}

	max := 0.0
	for _, m := range matches {
		if m.Confidence > max {
			max = m.Confidence
		}
	}

	// Category boost based on the highest-severity match.
	topCat := ""
	for _, m := range matches {
		if m.Confidence == max {
			topCat = string(m.Category)
			break
		}
	}
	switch topCat {
	case string(CategoryLLM01):
		max += 0.10
	case string(CategoryLLM06):
		max += 0.05
	}

	// Multi-match boost.
	extra := len(matches) - 1
	if extra > 0 {
		boost := 0.05 * float64(extra)
		if boost > 0.15 {
			boost = 0.15
		}
		max += boost
	}

	// Context adjustment.
	switch context {
	case "authenticated_operator":
		max -= 0.10
	case "internal_dev_tool":
		max -= 0.20
	case "untrusted_third_party":
		max += 0.10
	case "untrusted_document_content":
		max += 0.20
	}

	// Clamp.
	if max < 0 {
		max = 0
	}
	if max > 1 {
		max = 1
	}

	// Classify.
	switch {
	case max >= blockT:
		return Scored{Classification: ClassificationBlocked, Confidence: max}
	case max < cleanT:
		return Scored{Classification: ClassificationClean, Confidence: max}
	default:
		return Scored{Classification: ClassificationSuspicious, Confidence: max}
	}
}
