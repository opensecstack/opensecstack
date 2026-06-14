package attack

import (
	"regexp"
	"strings"
)

var techniqueIDPattern = regexp.MustCompile(`\bT\d{4}(?:\.\d{3})?\b`)

// StixKillChainPhase mirrors the STIX kill_chain_phases entry needed for
// extraction. The package does not import internal/stix to avoid a cycle.
type StixKillChainPhase struct {
	KillChainName string
	PhaseName     string
}

// StixExternalRef mirrors the STIX external_references entry needed for
// extraction.
type StixExternalRef struct {
	SourceName string
	ExternalID string
	URL        string
}

// FromKillChainPhases extracts technique mappings from a STIX object's
// kill_chain_phases. Only phases whose kill_chain_name is "mitre-attack"
// are considered; the phase name itself is not always a technique ID, so
// we scan for T-numbers in both kill_chain_name and phase_name.
func FromKillChainPhases(phases []StixKillChainPhase) []Mapping {
	seen := map[string]struct{}{}
	var out []Mapping
	for _, p := range phases {
		if !isMitreChain(p.KillChainName) {
			continue
		}
		for _, id := range techniqueIDPattern.FindAllString(p.PhaseName, -1) {
			if _, dup := seen[id]; dup {
				continue
			}
			if _, known := Lookup(id); !known {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, Mapping{
				TechniqueID: id,
				Source:      SourceFeed,
				Confidence:  90,
			})
		}
	}
	return out
}

// FromExternalRefs extracts technique mappings from STIX external_references.
// A ref is considered a technique ref if source_name starts with "mitre-attack"
// and external_id matches the T-number pattern.
func FromExternalRefs(refs []StixExternalRef) []Mapping {
	seen := map[string]struct{}{}
	out := make([]Mapping, 0, len(refs))
	for _, r := range refs {
		if !isMitreSource(r.SourceName) {
			continue
		}
		id := strings.TrimSpace(r.ExternalID)
		if !techniqueIDPattern.MatchString(id) {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		if _, known := Lookup(id); !known {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, Mapping{
			TechniqueID: id,
			Source:      SourceFeed,
			Confidence:  95,
		})
	}
	return out
}

// Merge combines several mapping sets and keeps the highest-confidence
// instance of each technique. Feed-sourced mappings win ties over auto.
func Merge(sets ...[]Mapping) []Mapping {
	best := map[string]Mapping{}
	for _, set := range sets {
		for _, m := range set {
			cur, ok := best[m.TechniqueID]
			if !ok {
				best[m.TechniqueID] = m
				continue
			}
			if m.Confidence > cur.Confidence {
				best[m.TechniqueID] = m
				continue
			}
			if m.Confidence == cur.Confidence && m.Source == SourceFeed && cur.Source != SourceFeed {
				best[m.TechniqueID] = m
			}
		}
	}
	out := make([]Mapping, 0, len(best))
	for _, m := range best {
		out = append(out, m)
	}
	return out
}

func isMitreChain(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	return n == "mitre-attack" || strings.HasPrefix(n, "mitre-")
}

func isMitreSource(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	return strings.HasPrefix(n, "mitre-attack")
}
