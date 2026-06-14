package attack

import "strings"

// rule is one auto-tag rule. The rule fires if every condition matches the
// IOC; when it fires, each technique in TechniqueIDs is assigned at the given
// confidence.
type rule struct {
	MatchType   string   // IOC type: "", "ipv4-addr", "domain-name", "url", "file", "email-addr"
	MatchLabel  string   // substring on any tag/label (lowercased)
	Techniques  []string // technique IDs this rule produces
	Confidence  int
}

// autoRules are tried in order; every match contributes mappings.
var autoRules = []rule{
	// Phishing
	{MatchLabel: "phish", Techniques: []string{"T1566", "T1566.002"}, Confidence: 70},
	{MatchType: "email-addr", MatchLabel: "phish", Techniques: []string{"T1566.001"}, Confidence: 80},

	// C2 / command-and-control
	{MatchLabel: "c2", Techniques: []string{"T1071"}, Confidence: 75},
	{MatchLabel: "command-and-control", Techniques: []string{"T1071"}, Confidence: 75},
	{MatchType: "domain-name", MatchLabel: "c2", Techniques: []string{"T1071.004"}, Confidence: 80},
	{MatchType: "url", MatchLabel: "c2", Techniques: []string{"T1071.001"}, Confidence: 80},

	// Malware delivery / user execution
	{MatchLabel: "malware", Techniques: []string{"T1204"}, Confidence: 65},
	{MatchLabel: "malware_download", Techniques: []string{"T1204.001", "T1105"}, Confidence: 75},
	{MatchLabel: "malicious-activity", Techniques: []string{"T1204"}, Confidence: 55},

	// Exploit / RCE
	{MatchLabel: "exploit", Techniques: []string{"T1190"}, Confidence: 70},
	{MatchLabel: "rce", Techniques: []string{"T1190"}, Confidence: 80},

	// Ransomware / impact
	{MatchLabel: "ransomware", Techniques: []string{"T1486", "T1490"}, Confidence: 85},

	// Credential / brute-force
	{MatchLabel: "bruteforce", Techniques: []string{"T1110"}, Confidence: 80},
	{MatchLabel: "credential", Techniques: []string{"T1555"}, Confidence: 65},

	// Tunneling
	{MatchLabel: "tunnel", Techniques: []string{"T1572"}, Confidence: 70},

	// Obfuscation
	{MatchLabel: "obfuscated", Techniques: []string{"T1027"}, Confidence: 70},
}

// Auto returns technique mappings derived from an IOC's type + tags. Each
// distinct technique is emitted at most once at the highest-confidence rule
// that produced it.
func Auto(iocType string, tags []string) []Mapping {
	normalisedTags := make([]string, 0, len(tags))
	for _, t := range tags {
		normalisedTags = append(normalisedTags, strings.ToLower(strings.TrimSpace(t)))
	}

	best := map[string]int{}
	for _, r := range autoRules {
		if r.MatchType != "" && r.MatchType != iocType {
			continue
		}
		if r.MatchLabel != "" && !matchesAnyTag(normalisedTags, r.MatchLabel) {
			continue
		}
		for _, id := range r.Techniques {
			if cur, ok := best[id]; !ok || r.Confidence > cur {
				best[id] = r.Confidence
			}
		}
	}

	out := make([]Mapping, 0, len(best))
	for id, conf := range best {
		if _, known := Lookup(id); !known {
			continue
		}
		out = append(out, Mapping{
			TechniqueID: id,
			Source:      SourceAuto,
			Confidence:  conf,
		})
	}
	return out
}

func matchesAnyTag(tags []string, needle string) bool {
	for _, t := range tags {
		if strings.Contains(t, needle) {
			return true
		}
	}
	return false
}
