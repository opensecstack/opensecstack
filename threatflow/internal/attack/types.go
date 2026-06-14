// Package attack provides MITRE ATT&CK technique mapping for IOCs. Techniques
// may come from three sources, in descending authority:
//
//  1. Feed-provided — the indicator ships with kill_chain_phases or
//     external_references pointing to mitre-attack.
//  2. Rule-based auto-tag — deterministic rules applied to an IOC's labels,
//     type, and value (e.g. "c2" label → T1071).
//  3. Manual — set by an analyst via the API.
//
// Each tag stored in ttp_tags carries a `source` column so downstream
// consumers can weight feed-provided mappings above heuristic ones.
package attack

// Source is the provenance of a TTP tag. Mirrors the CHECK constraint on
// ttp_tags.source: (`auto`, `feed`, `manual`).
type Source string

const (
	SourceAuto   Source = "auto"
	SourceFeed   Source = "feed"
	SourceManual Source = "manual"
)

// Technique is a MITRE ATT&CK technique reference.
type Technique struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Tactic      string `json:"tactic"`
	Description string `json:"description,omitempty"`
}

// Mapping is one IOC-to-technique association with provenance.
type Mapping struct {
	TechniqueID string
	Source      Source
	Confidence  int
}
