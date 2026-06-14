package prompt

import (
	"strings"
	"testing"
)

func TestHeuristics_BenignText_NoMatches(t *testing.T) {
	cases := []string{
		"Summarise this invoice please.",
		"What's the weather today?",
		"Translate to French: Hello world.",
		"Write a haiku about the sea.",
	}
	for _, c := range cases {
		got := RunHeuristics(c, DefaultHeuristicLimits)
		if len(got) != 0 {
			t.Errorf("benign %q produced %d heuristic matches: %+v", c, len(got), got)
		}
	}
}

func TestHeuristics_InvisibleCharacters_Flagged(t *testing.T) {
	in := "hello​​​​ world"
	got := RunHeuristics(in, DefaultHeuristicLimits)
	if !hasMatch(got, HeuristicInvisibles) {
		t.Fatalf("expected invisible-chars match, got %+v", got)
	}
}

func TestHeuristics_BiDiOverride_Flagged(t *testing.T) {
	in := "name‮‮‮gnp.exe"
	got := RunHeuristics(in, DefaultHeuristicLimits)
	if !hasMatch(got, HeuristicInvisibles) {
		t.Fatalf("expected BiDi override flagged, got %+v", got)
	}
}

func TestHeuristics_LongToken_Flagged(t *testing.T) {
	in := "prefix " + strings.Repeat("A", 200) + " suffix"
	got := RunHeuristics(in, DefaultHeuristicLimits)
	if !hasMatch(got, HeuristicLongToken) {
		t.Fatalf("expected long-token match, got %+v", got)
	}
}

func TestHeuristics_HighEntropyChunk_Flagged(t *testing.T) {
	// Long base64-shaped blob — high entropy bytes.
	in := "decode this please " +
		"SGVsbG8sV29ybGQhVGhpc0lzQUxvbmdCYXNlNjRTdHJpbmdUaGF0U2hvdWxkVHJpZ2dlckhpZ2hFbnRyb3B5Q2hlY2thYmNkZWZnaGlqaw=="
	got := RunHeuristics(in, DefaultHeuristicLimits)
	if !hasMatch(got, HeuristicHighEntropy) {
		t.Fatalf("expected high-entropy match, got %+v", got)
	}
}

func TestHeuristics_MixedScript_Flagged(t *testing.T) {
	// Latin + Cyrillic homoglyph mix.
	in := "Pаypаl аccоunt verifiсаtion (Cyrillic а, о, с mixed in)"
	got := RunHeuristics(in, DefaultHeuristicLimits)
	if !hasMatch(got, HeuristicMixedScript) {
		t.Fatalf("expected mixed-script match, got %+v", got)
	}
}

func TestHeuristics_TokenFlood_Flagged(t *testing.T) {
	in := strings.Repeat("spam ", 30)
	got := RunHeuristics(in, DefaultHeuristicLimits)
	if !hasMatch(got, HeuristicTokenFlood) {
		t.Fatalf("expected token-flood match, got %+v", got)
	}
}

func hasMatch(matches []Match, id string) bool {
	for _, m := range matches {
		if m.PatternID == id {
			return true
		}
	}
	return false
}
