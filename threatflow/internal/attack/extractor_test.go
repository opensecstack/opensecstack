package attack

import "testing"

func TestFromKillChainPhases_MitreOnly(t *testing.T) {
	phases := []StixKillChainPhase{
		{KillChainName: "mitre-attack", PhaseName: "command-and-control T1071"},
		{KillChainName: "lockheed-martin", PhaseName: "actions-on-objectives"},
	}
	ms := FromKillChainPhases(phases)
	if len(ms) != 1 {
		t.Fatalf("want 1 mapping, got %d", len(ms))
	}
	if ms[0].TechniqueID != "T1071" || ms[0].Source != SourceFeed {
		t.Errorf("unexpected: %+v", ms[0])
	}
}

func TestFromExternalRefs(t *testing.T) {
	refs := []StixExternalRef{
		{SourceName: "mitre-attack", ExternalID: "T1566.002"},
		{SourceName: "capec", ExternalID: "CAPEC-163"},
		{SourceName: "mitre-attack", ExternalID: "T9999"}, // unknown → filtered
	}
	ms := FromExternalRefs(refs)
	if len(ms) != 1 {
		t.Fatalf("want 1 mapping (T1566.002), got %d: %v", len(ms), ms)
	}
	if ms[0].TechniqueID != "T1566.002" {
		t.Errorf("unexpected: %+v", ms[0])
	}
}

func TestMerge_FeedBeatsAutoAtSameConfidence(t *testing.T) {
	feed := []Mapping{{TechniqueID: "T1071", Source: SourceFeed, Confidence: 75}}
	auto := []Mapping{{TechniqueID: "T1071", Source: SourceAuto, Confidence: 75}}

	merged := Merge(auto, feed)
	if len(merged) != 1 {
		t.Fatalf("want 1 merged, got %d", len(merged))
	}
	if merged[0].Source != SourceFeed {
		t.Errorf("feed should win ties; got %s", merged[0].Source)
	}
}

func TestMerge_HighestConfidenceWins(t *testing.T) {
	auto := []Mapping{{TechniqueID: "T1566", Source: SourceAuto, Confidence: 70}}
	feed := []Mapping{{TechniqueID: "T1566", Source: SourceFeed, Confidence: 50}}

	merged := Merge(auto, feed)
	if len(merged) != 1 {
		t.Fatalf("want 1 merged, got %d", len(merged))
	}
	if merged[0].Confidence != 70 {
		t.Errorf("want conf 70, got %d", merged[0].Confidence)
	}
}
