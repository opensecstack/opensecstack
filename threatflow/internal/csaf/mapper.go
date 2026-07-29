package csaf

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/opensecstack/threatflow/internal/db/store"
)

// stixVulnerabilityNamespace is a fixed UUID namespace used to derive
// deterministic STIX object IDs for CSAF-sourced vulnerabilities via
// uuid.NewSHA1. Deterministic IDs make re-ingesting the same
// (tracking.id, version, cve-or-index) idempotent — InsertObject's
// `ON CONFLICT (stix_id) DO NOTHING` then naturally dedupes retries of the
// same revision instead of accumulating duplicate STIX objects.
var stixVulnerabilityNamespace = uuid.MustParse("6c7e9b8a-2f0d-4b1a-9e3c-2a7d9f6b0c11")

// StixVulnerabilityObject is one STIX 2.1 "vulnerability" object derived
// from a CSAF vulnerabilities[] entry, ready to hand to store.StixStore.
type StixVulnerabilityObject struct {
	StixID  string
	Content json.RawMessage
}

// MappedAdvisory is the full result of mapping one CSAF document: the
// advisory row, its vulnerabilities (with remediations nested and
// StixObjectRef already populated), its products, and the STIX objects that
// must be persisted (via StixStore) before the advisory rows are written,
// since advisory_vulnerabilities.stix_object_ref is a foreign key into
// stix_objects.stix_id.
type MappedAdvisory struct {
	Advisory        *store.Advisory
	Vulnerabilities []*store.AdvisoryVulnerability
	Products        []*store.AdvisoryProduct
	StixObjects     []StixVulnerabilityObject
	StixBundleID    string // deterministic stix_id for the import bundle
}

// Map converts a parsed, validated CSAF document into ThreatFlow's storage
// shape: STIX 2.1 Vulnerability objects for every vulnerabilities[] entry
// (the canonical, correlatable representation ADR-001 mandates), plus the
// CSAF-specific structure that has no STIX equivalent — product_tree and
// remediations — captured verbatim in the advisory-specific tables added by
// migration 009. source identifies the pusher (e.g. "opencsirt") and is
// threaded through to both the advisories.source column and the STIX
// stix_bundles.source column.
func Map(doc *Document, source string) (*MappedAdvisory, error) {
	initial, current, err := doc.releaseTimes()
	if err != nil {
		return nil, fmt.Errorf("parse tracking dates: %w", err)
	}

	trackingID := doc.Document.Tracking.ID
	version := doc.Version()

	status := doc.Document.Tracking.Status
	if status == "" {
		status = "final"
	}
	lang := doc.Document.Lang
	if lang == "" {
		lang = "en"
	}

	rawDoc, err := json.Marshal(rawDocumentForStorage(doc))
	if err != nil {
		return nil, fmt.Errorf("marshal raw document: %w", err)
	}

	advisory := &store.Advisory{
		TrackingID:         trackingID,
		CSAFVersion:        orDefault(doc.Document.CSAFVersion, "2.0"),
		Revision:           version,
		Category:           doc.Document.Category,
		Title:              doc.Document.Title,
		Lang:               lang,
		Status:             status,
		TLPLabel:           doc.Document.Distribution.TLP.Label,
		PublisherName:      doc.Document.Publisher.Name,
		PublisherCategory:  doc.Document.Publisher.Category,
		PublisherNamespace: doc.Document.Publisher.Namespace,
		InitialReleaseDate: initial,
		CurrentReleaseDate: current,
		Source:             source,
		RawDocument:        rawDoc,
	}

	stixObjects := make([]StixVulnerabilityObject, 0, len(doc.Vulnerabilities))
	vulns := make([]*store.AdvisoryVulnerability, 0, len(doc.Vulnerabilities))

	for idx, v := range doc.Vulnerabilities {
		key := v.CVE
		if key == "" {
			key = fmt.Sprintf("idx-%d", idx)
		}
		stixID := "vulnerability--" + uuid.NewSHA1(stixVulnerabilityNamespace,
			[]byte(trackingID+"|"+version+"|"+key)).String()

		obj, err := buildStixVulnerability(stixID, v, initial, current)
		if err != nil {
			return nil, fmt.Errorf("build stix vulnerability for %q: %w", v.Title, err)
		}
		stixObjects = append(stixObjects, StixVulnerabilityObject{StixID: stixID, Content: obj})

		remediations := make([]*store.AdvisoryRemediation, 0, len(v.Remediations))
		for _, r := range v.Remediations {
			remediations = append(remediations, &store.AdvisoryRemediation{
				Category:   r.Category,
				Details:    r.Details,
				ProductIDs: orEmptySlice(r.ProductIDs),
				URL:        r.URL,
			})
		}

		vulns = append(vulns, &store.AdvisoryVulnerability{
			CVE:           v.CVE,
			Title:         v.Title,
			Notes:         rawMessage(v.Notes),
			ProductStatus: rawMessage(v.ProductStatus),
			Scores:        rawMessage(v.Scores),
			References:    rawMessage(v.References),
			StixObjectRef: stixID,
			Remediations:  remediations,
		})
	}

	var products []*store.AdvisoryProduct
	if doc.ProductTree != nil {
		products = make([]*store.AdvisoryProduct, 0, len(doc.ProductTree.FullProductNames))
		for _, p := range doc.ProductTree.FullProductNames {
			products = append(products, &store.AdvisoryProduct{
				ProductID: p.ProductID,
				Name:      p.Name,
				CPE:       p.CPE,
				PURL:      p.PURL,
			})
		}
	}

	bundleID := "bundle--" + uuid.NewSHA1(stixVulnerabilityNamespace,
		[]byte("advisory-bundle|"+trackingID+"|"+version)).String()

	return &MappedAdvisory{
		Advisory:        advisory,
		Vulnerabilities: vulns,
		Products:        products,
		StixObjects:     stixObjects,
		StixBundleID:    bundleID,
	}, nil
}

// buildStixVulnerability renders a CSAF vulnerabilities[] entry as a STIX
// 2.1 "vulnerability" object (§4.14). The CVE (when present) is carried as
// an external_references entry with source_name "cve" — the conventional
// STIX encoding for CVE identifiers, matching how MITRE ATT&CK technique
// IDs are carried on indicators elsewhere in this codebase
// (internal/attack).
func buildStixVulnerability(stixID string, v Vulnerability, created, modified time.Time) (json.RawMessage, error) {
	extRefs := make([]map[string]string, 0, len(v.References)+1)
	if v.CVE != "" {
		extRefs = append(extRefs, map[string]string{
			"source_name": "cve",
			"external_id": v.CVE,
		})
	}
	for _, r := range v.References {
		ref := map[string]string{"source_name": "csaf"}
		if url, ok := r["url"]; ok {
			ref["url"] = url
		}
		if summary, ok := r["summary"]; ok {
			ref["description"] = summary
		}
		extRefs = append(extRefs, ref)
	}

	description := ""
	for _, n := range v.Notes {
		if n["category"] == "description" || n["category"] == "summary" {
			description = n["text"]
			break
		}
	}

	obj := map[string]any{
		"type":         "vulnerability",
		"spec_version": "2.1",
		"id":           stixID,
		"created":      created.UTC().Format(time.RFC3339),
		"modified":     modified.UTC().Format(time.RFC3339),
		"name":         v.Title,
	}
	if description != "" {
		obj["description"] = description
	}
	if len(extRefs) > 0 {
		obj["external_references"] = extRefs
	}
	return json.Marshal(obj)
}

// rawDocumentForStorage re-serialises the parsed document so raw_document
// stores the document as ThreatFlow understood it (normalised field
// presence) rather than re-storing the caller's original bytes a second
// time — the original bytes are already content-addressed via
// advisory_revisions.document_hash / raw_document.
func rawDocumentForStorage(doc *Document) *Document {
	return doc
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func orEmptySlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
