// Package csaf ingests CSAF 2.0 advisory documents (as pushed by OpenCSIRT's
// PushAdvisory, see opencsirt/internal/integrations/threatflow.go) and maps
// them onto ThreatFlow's canonical STIX 2.1 model plus a set of
// advisory-specific tables for CSAF structure that has no clean STIX
// equivalent (product_tree, remediations). See
// threatflow/adrs/004-opencsirt-advisory-ingestion-gap.md for the design
// rationale.
//
// The Go types here mirror the Pydantic models in
// opencsirt/python/advisory/csaf.py field-for-field (same JSON keys, same
// nesting) since that generator is the only producer of this payload today.
package csaf

import "encoding/json"

// Document is the top-level CSAF 2.0 document.
type Document struct {
	Document        DocumentMeta    `json:"document"`
	ProductTree     *ProductTree    `json:"product_tree,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

// DocumentMeta is CSAF's `document` block.
type DocumentMeta struct {
	Category     string       `json:"category"`
	CSAFVersion  string       `json:"csaf_version"`
	Title        string       `json:"title"`
	Publisher    Publisher    `json:"publisher"`
	Tracking     Tracking     `json:"tracking"`
	Distribution Distribution `json:"distribution"`
	Notes        []NoteOrRef  `json:"notes,omitempty"`
	References   []NoteOrRef  `json:"references,omitempty"`
	Lang         string       `json:"lang,omitempty"`
}

// Publisher is `document.publisher`.
type Publisher struct {
	Category         string `json:"category"`
	Name             string `json:"name"`
	Namespace        string `json:"namespace"`
	ContactDetails   string `json:"contact_details,omitempty"`
	IssuingAuthority string `json:"issuing_authority,omitempty"`
}

// TLP is a Traffic Light Protocol marking.
type TLP struct {
	Label string `json:"label"`
	URL   string `json:"url,omitempty"`
}

// Distribution is `document.distribution`.
type Distribution struct {
	TLP TLP `json:"tlp"`
}

// RevisionEntry is one entry in `tracking.revision_history`.
type RevisionEntry struct {
	Number  string `json:"number"`
	Date    string `json:"date"`
	Summary string `json:"summary"`
}

// Tracking is `document.tracking` — the revision/dedup key for ingestion
// lives here: Tracking.ID + Tracking.Version (see internal/csaf.RevisionKey).
type Tracking struct {
	ID                 string            `json:"id"`
	InitialReleaseDate string            `json:"initial_release_date"`
	CurrentReleaseDate string            `json:"current_release_date"`
	RevisionHistory    []RevisionEntry   `json:"revision_history,omitempty"`
	Status             string            `json:"status,omitempty"`
	Version            string            `json:"version,omitempty"`
	Generator          map[string]string `json:"generator,omitempty"`
}

// NoteOrRef covers both CSAF `notes[]` and `references[]` entries — both are
// free-form string maps in the upstream schema (category/title/text or
// summary/url/category).
type NoteOrRef map[string]string

// ProductTree is `product_tree`.
type ProductTree struct {
	FullProductNames []ProductIdentifier `json:"full_product_names,omitempty"`
}

// ProductIdentifier is one `product_tree.full_product_names[]` entry.
type ProductIdentifier struct {
	ProductID string `json:"product_id"`
	Name      string `json:"name"`
	CPE       string `json:"cpe,omitempty"`
	PURL      string `json:"purl,omitempty"`
}

// CVSS is one `vulnerabilities[].scores[]` entry.
type CVSS struct {
	Products []string       `json:"products"`
	CVSSV3   map[string]any `json:"cvss_v3,omitempty"`
}

// Remediation is one `vulnerabilities[].remediations[]` entry.
type Remediation struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids,omitempty"`
	URL        string   `json:"url,omitempty"`
}

// Vulnerability is one `vulnerabilities[]` entry.
type Vulnerability struct {
	CVE           string              `json:"cve,omitempty"`
	Title         string              `json:"title"`
	Notes         []NoteOrRef         `json:"notes,omitempty"`
	ProductStatus map[string][]string `json:"product_status,omitempty"`
	Scores        []CVSS              `json:"scores,omitempty"`
	Remediations  []Remediation       `json:"remediations,omitempty"`
	References    []NoteOrRef         `json:"references,omitempty"`
	IDs           []NoteOrRef         `json:"ids,omitempty"`
}

// rawMessage is a small helper so callers that need to re-marshal a field
// into JSONB for storage don't have to re-derive the encoding rules.
func rawMessage(v any) json.RawMessage {
	if v == nil {
		return json.RawMessage(`null`)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`null`)
	}
	return b
}
