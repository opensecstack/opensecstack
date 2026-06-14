package attack

import "testing"

func TestAuto_PhishingLabel(t *testing.T) {
	m := Auto("url", []string{"phishing"})
	if !hasTechnique(m, "T1566") {
		t.Errorf("phishing tag should map to T1566; got %v", ids(m))
	}
}

func TestAuto_C2DomainSubTechnique(t *testing.T) {
	m := Auto("domain-name", []string{"c2"})
	if !hasTechnique(m, "T1071.004") {
		t.Errorf("c2 on domain should map to T1071.004 (DNS); got %v", ids(m))
	}
}

func TestAuto_RansomwareImpact(t *testing.T) {
	m := Auto("file", []string{"ransomware"})
	if !hasTechnique(m, "T1486") || !hasTechnique(m, "T1490") {
		t.Errorf("ransomware should map to impact techniques; got %v", ids(m))
	}
}

func TestAuto_UnknownLabel_NoMappings(t *testing.T) {
	m := Auto("ipv4-addr", []string{"unrelated-tag"})
	if len(m) != 0 {
		t.Errorf("unrelated tag should produce no mappings; got %v", ids(m))
	}
}

func TestAuto_HighestConfidenceWins(t *testing.T) {
	// "c2" (conf 75) + matching on domain-name adds T1071.004 (conf 80)
	m := Auto("domain-name", []string{"c2"})
	for _, mp := range m {
		if mp.TechniqueID == "T1071" && mp.Confidence != 75 {
			t.Errorf("T1071 confidence should remain 75; got %d", mp.Confidence)
		}
	}
}

func hasTechnique(ms []Mapping, id string) bool {
	for _, m := range ms {
		if m.TechniqueID == id {
			return true
		}
	}
	return false
}

func ids(ms []Mapping) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.TechniqueID)
	}
	return out
}
