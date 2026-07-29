// Package stix implements STIX 2.1 bundle parsing, validation, and conversion
// to ThreatFlow IOCs. See https://docs.oasis-open.org/cti/stix/v2.1/ for the
// full specification. This package targets the subset of STIX produced by
// mainstream feeds (TAXII 2.1, AlienVault OTX, MISP).
package stix

import (
	"encoding/json"
	"time"
)

// SpecVersion is the STIX version this package implements.
const SpecVersion = "2.1"

// Bundle is a STIX 2.1 bundle — the top-level container for a set of objects.
type Bundle struct {
	Type        string          `json:"type"`
	ID          string          `json:"id"`
	SpecVersion string          `json:"spec_version,omitempty"`
	Objects     json.RawMessage `json:"objects"`
}

// Object is the common envelope every STIX domain object shares. The raw JSON
// is preserved so typed accessors can decode the full object on demand.
type Object struct {
	Type         string          `json:"type"`
	ID           string          `json:"id"`
	SpecVersion  string          `json:"spec_version,omitempty"`
	Created      time.Time       `json:"created,omitempty"`
	Modified     time.Time       `json:"modified,omitempty"`
	Revoked      bool            `json:"revoked,omitempty"`
	Labels       []string        `json:"labels,omitempty"`
	Confidence   int             `json:"confidence,omitempty"`
	ExternalRefs []ExternalRef   `json:"external_references,omitempty"`
	Raw          json.RawMessage `json:"-"`
}

// ExternalRef is an entry in a STIX object's external_references array.
type ExternalRef struct {
	SourceName  string `json:"source_name"`
	Description string `json:"description,omitempty"`
	URL         string `json:"url,omitempty"`
	ExternalID  string `json:"external_id,omitempty"`
}

// Indicator is a STIX 2.1 indicator — the primary source of IOC data.
type Indicator struct {
	Object
	Name           string    `json:"name,omitempty"`
	Description    string    `json:"description,omitempty"`
	IndicatorTypes []string  `json:"indicator_types,omitempty"`
	Pattern        string    `json:"pattern"`
	PatternType    string    `json:"pattern_type,omitempty"`
	ValidFrom      time.Time `json:"valid_from,omitempty"`
	ValidUntil     time.Time `json:"valid_until,omitempty"`
	KillChain      []KillChainPhase `json:"kill_chain_phases,omitempty"`
}

// KillChainPhase is a lockheed/mitre kill chain phase reference.
type KillChainPhase struct {
	KillChainName string `json:"kill_chain_name"`
	PhaseName     string `json:"phase_name"`
}

// Malware is a STIX 2.1 malware object.
type Malware struct {
	Object
	Name          string   `json:"name"`
	Description   string   `json:"description,omitempty"`
	MalwareTypes  []string `json:"malware_types,omitempty"`
	IsFamily      bool     `json:"is_family,omitempty"`
	Aliases       []string `json:"aliases,omitempty"`
	KillChain     []KillChainPhase `json:"kill_chain_phases,omitempty"`
}

// AttackPattern is a STIX 2.1 attack-pattern — typically a MITRE ATT&CK technique.
type AttackPattern struct {
	Object
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	KillChain   []KillChainPhase `json:"kill_chain_phases,omitempty"`
}

// Vulnerability is a STIX 2.1 vulnerability object (§4.14) — a weakness that
// can be exploited, typically identified by a CVE carried in
// external_references. Unlike Indicator, it has no pattern: it represents
// the vulnerability itself, not a detection rule for it. This is the object
// CSAF `vulnerabilities[]` entries are mapped onto (see internal/csaf).
type Vulnerability struct {
	Object
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// Relationship connects two STIX objects (e.g. malware USES attack-pattern).
type Relationship struct {
	Object
	RelationshipType string `json:"relationship_type"`
	SourceRef        string `json:"source_ref"`
	TargetRef        string `json:"target_ref"`
	Description      string `json:"description,omitempty"`
}
