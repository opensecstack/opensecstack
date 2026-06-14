package attack

import "testing"

// BenchmarkAuto_AllRules fires the auto-tagger against a realistic indicator
// (3 tags, URL type) so every rule has a chance to match. This runs once per
// ingested indicator inside stix.Importer.
func BenchmarkAuto_AllRules(b *testing.B) {
	tags := []string{"phishing", "c2", "malware_download"}
	for i := 0; i < b.N; i++ {
		_ = Auto("url", tags)
	}
}

// BenchmarkMerge merges two mapping sets of 5 entries each — representative
// of the feed + auto blend the STIX importer computes per indicator.
func BenchmarkMerge(b *testing.B) {
	feed := []Mapping{
		{TechniqueID: "T1071", Source: SourceFeed, Confidence: 90},
		{TechniqueID: "T1566", Source: SourceFeed, Confidence: 85},
		{TechniqueID: "T1204", Source: SourceFeed, Confidence: 70},
		{TechniqueID: "T1027", Source: SourceFeed, Confidence: 60},
		{TechniqueID: "T1105", Source: SourceFeed, Confidence: 65},
	}
	auto := []Mapping{
		{TechniqueID: "T1071", Source: SourceAuto, Confidence: 75},
		{TechniqueID: "T1566", Source: SourceAuto, Confidence: 70},
		{TechniqueID: "T1190", Source: SourceAuto, Confidence: 80},
		{TechniqueID: "T1486", Source: SourceAuto, Confidence: 85},
		{TechniqueID: "T1110", Source: SourceAuto, Confidence: 65},
	}
	for i := 0; i < b.N; i++ {
		_ = Merge(feed, auto)
	}
}
