package prompt

import "testing"

func TestScore_NoMatches_IsClean(t *testing.T) {
	s := Score(nil, "user_chat_input", 0.3, 0.7)
	if s.Classification != ClassificationClean {
		t.Fatalf("want CLEAN, got %s", s.Classification)
	}
	if s.Confidence != 0 {
		t.Fatalf("want 0 confidence, got %v", s.Confidence)
	}
}

func TestScore_SingleHighConfidenceLLM01_Blocks(t *testing.T) {
	matches := []Match{
		{PatternID: "LLM01.instruction_override.v1", Category: CategoryLLM01, Confidence: 0.95},
	}
	s := Score(matches, "user_chat_input", 0.3, 0.7)
	if s.Classification != ClassificationBlocked {
		t.Fatalf("want BLOCKED, got %s (conf %v)", s.Classification, s.Confidence)
	}
	// 0.95 + 0.10 category boost = 1.05 clamped to 1.0.
	if s.Confidence != 1.0 {
		t.Fatalf("want confidence 1.0 after boost+clamp, got %v", s.Confidence)
	}
}

func TestScore_MediumConfidence_IsSuspicious(t *testing.T) {
	matches := []Match{
		{PatternID: "LLM04.recursive_generation.v1", Category: CategoryLLM04, Confidence: 0.6},
	}
	s := Score(matches, "user_chat_input", 0.3, 0.7)
	if s.Classification != ClassificationSuspicious {
		t.Fatalf("want SUSPICIOUS, got %s", s.Classification)
	}
}

func TestScore_LowConfidence_IsClean(t *testing.T) {
	matches := []Match{
		{PatternID: "LLM10.version_probe.v1", Category: CategoryLLM10, Confidence: 0.2},
	}
	s := Score(matches, "user_chat_input", 0.3, 0.7)
	if s.Classification != ClassificationClean {
		t.Fatalf("want CLEAN for 0.2 confidence, got %s", s.Classification)
	}
}

func TestScore_MultiMatchBoost_CapsAt015(t *testing.T) {
	var matches []Match
	for i := 0; i < 10; i++ {
		matches = append(matches, Match{PatternID: "x", Category: CategoryLLM04, Confidence: 0.5})
	}
	s := Score(matches, "user_chat_input", 0.3, 0.7)
	// max 0.5 + no category boost + 0.15 multi-match cap = 0.65 → SUSPICIOUS.
	if s.Confidence > 0.66 || s.Confidence < 0.64 {
		t.Fatalf("want ~0.65 after capped boost, got %v", s.Confidence)
	}
}

func TestScore_TrustedContext_Reduces(t *testing.T) {
	matches := []Match{
		{PatternID: "LLM04.recursive_generation.v1", Category: CategoryLLM04, Confidence: 0.5},
	}
	normal := Score(matches, "user_chat_input", 0.3, 0.7)
	trusted := Score(matches, "internal_dev_tool", 0.3, 0.7)
	if trusted.Confidence >= normal.Confidence {
		t.Fatalf("trusted context should reduce confidence: normal=%v trusted=%v",
			normal.Confidence, trusted.Confidence)
	}
}

func TestScore_UntrustedDocument_Elevates(t *testing.T) {
	matches := []Match{
		{PatternID: "LLM01.indirect.embedded_instruction.v1", Category: CategoryLLM01, Confidence: 0.6},
	}
	normal := Score(matches, "user_chat_input", 0.3, 0.7)
	doc := Score(matches, "untrusted_document_content", 0.3, 0.7)
	if doc.Confidence <= normal.Confidence {
		t.Fatalf("untrusted doc context should raise confidence: normal=%v doc=%v",
			normal.Confidence, doc.Confidence)
	}
}
