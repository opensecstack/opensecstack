package phishing

import "testing"

func TestScore_NoMatches_IsClean(t *testing.T) {
	s := Score(nil, KindURL, 0.3, 0.7)
	if s.Classification != ClassificationClean || s.Confidence != 0 {
		t.Fatalf("want CLEAN/0, got %s/%v", s.Classification, s.Confidence)
	}
}

func TestScore_HighCredHarvest_Blocks(t *testing.T) {
	matches := []Match{
		{PatternID: "PH.cred.ssn_request.v1", Category: CategoryCredentialHarvest, Confidence: 0.95},
	}
	s := Score(matches, KindEmail, 0.3, 0.7)
	if s.Classification != ClassificationBlocked {
		t.Fatalf("want BLOCKED, got %s (conf=%v)", s.Classification, s.Confidence)
	}
	// 0.95 + 0.15 (cat) + 0.10 (email harvest boost) clamped to 1.0.
	if s.Confidence != 1.0 {
		t.Fatalf("want clamp to 1.0, got %v", s.Confidence)
	}
}

func TestScore_URLObfBoost_Applied(t *testing.T) {
	matches := []Match{
		{PatternID: "PH.url.userinfo_at.v1", Category: CategoryURLObfuscation, Confidence: 0.7},
	}
	s := Score(matches, KindURL, 0.3, 0.7)
	// 0.7 + 0.10 = 0.80 → BLOCKED.
	if s.Classification != ClassificationBlocked {
		t.Fatalf("want BLOCKED, got %s (conf=%v)", s.Classification, s.Confidence)
	}
}

func TestScore_LowConfidence_IsClean(t *testing.T) {
	matches := []Match{
		{PatternID: "PH.x", Category: CategorySuspiciousDomain, Confidence: 0.2},
	}
	s := Score(matches, KindURL, 0.3, 0.7)
	if s.Classification != ClassificationClean {
		t.Fatalf("want CLEAN, got %s", s.Classification)
	}
}

func TestScore_UrgencyOnly_Suspicious(t *testing.T) {
	matches := []Match{
		{PatternID: "PH.urgency.x", Category: CategoryUrgency, Confidence: 0.55},
	}
	s := Score(matches, KindEmail, 0.3, 0.7)
	// 0.55 + 0.05 = 0.60 → SUSPICIOUS.
	if s.Classification != ClassificationSuspicious {
		t.Fatalf("want SUSPICIOUS, got %s (conf=%v)", s.Classification, s.Confidence)
	}
}

func TestScore_MultiMatchBoost_CapsAt015(t *testing.T) {
	var matches []Match
	for i := 0; i < 10; i++ {
		matches = append(matches, Match{PatternID: "x", Category: CategorySuspiciousDomain, Confidence: 0.5})
	}
	s := Score(matches, KindURL, 0.3, 0.7)
	// 0.5 + no cat boost + 0.15 cap = 0.65.
	if s.Confidence < 0.64 || s.Confidence > 0.66 {
		t.Fatalf("want ~0.65, got %v", s.Confidence)
	}
}

func TestScore_EmailKindBoost_OnHarvest(t *testing.T) {
	matches := []Match{
		{PatternID: "x", Category: CategoryCredentialHarvest, Confidence: 0.5},
	}
	url := Score(matches, KindURL, 0.3, 0.7)
	email := Score(matches, KindEmail, 0.3, 0.7)
	if email.Confidence <= url.Confidence {
		t.Fatalf("email kind should boost harvest: url=%v email=%v",
			url.Confidence, email.Confidence)
	}
}

func TestScore_EmailKindBoost_NotAppliedOnUrgency(t *testing.T) {
	matches := []Match{
		{PatternID: "x", Category: CategoryUrgency, Confidence: 0.5},
	}
	url := Score(matches, KindURL, 0.3, 0.7)
	email := Score(matches, KindEmail, 0.3, 0.7)
	if email.Confidence != url.Confidence {
		t.Fatalf("urgency should not get email-kind boost: url=%v email=%v",
			url.Confidence, email.Confidence)
	}
}
