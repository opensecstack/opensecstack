package csaf

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMap_ProducesOneStixVulnerabilityPerCVE(t *testing.T) {
	doc, err := ParseDocument([]byte(validCSAF))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	mapped, err := Map(doc, "opencsirt")
	if err != nil {
		t.Fatalf("map: %v", err)
	}

	if len(mapped.StixObjects) != 1 {
		t.Fatalf("want 1 stix object, got %d", len(mapped.StixObjects))
	}
	obj := mapped.StixObjects[0]
	if !strings.HasPrefix(obj.StixID, "vulnerability--") {
		t.Errorf("stix id = %q, want vulnerability-- prefix", obj.StixID)
	}

	var decoded map[string]any
	if err := json.Unmarshal(obj.Content, &decoded); err != nil {
		t.Fatalf("decode stix object: %v", err)
	}
	if decoded["type"] != "vulnerability" {
		t.Errorf("type = %v, want vulnerability", decoded["type"])
	}
	if decoded["name"] != "CVE-2026-00001 — Example RCE in Widget" {
		t.Errorf("name = %v", decoded["name"])
	}
	refs, ok := decoded["external_references"].([]any)
	if !ok || len(refs) == 0 {
		t.Fatalf("expected external_references with a CVE entry, got %v", decoded["external_references"])
	}
	firstRef := refs[0].(map[string]any)
	if firstRef["source_name"] != "cve" || firstRef["external_id"] != "CVE-2026-00001" {
		t.Errorf("first external_reference = %v, want cve/CVE-2026-00001", firstRef)
	}
}

func TestMap_PreservesRemediationsAndProductsInStoreRows(t *testing.T) {
	doc, err := ParseDocument([]byte(validCSAF))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	mapped, err := Map(doc, "opencsirt")
	if err != nil {
		t.Fatalf("map: %v", err)
	}

	if len(mapped.Products) != 1 || mapped.Products[0].ProductID != "CSAFPID-1" {
		t.Fatalf("products = %+v, want one CSAFPID-1", mapped.Products)
	}
	if mapped.Products[0].CPE != "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*" {
		t.Errorf("cpe not preserved: %+v", mapped.Products[0])
	}

	if len(mapped.Vulnerabilities) != 1 {
		t.Fatalf("want 1 vulnerability row, got %d", len(mapped.Vulnerabilities))
	}
	v := mapped.Vulnerabilities[0]
	if v.StixObjectRef != mapped.StixObjects[0].StixID {
		t.Errorf("StixObjectRef = %q, want %q", v.StixObjectRef, mapped.StixObjects[0].StixID)
	}
	if len(v.Remediations) != 1 {
		t.Fatalf("want 1 remediation, got %d", len(v.Remediations))
	}
	rem := v.Remediations[0]
	if rem.Category != "vendor_fix" || rem.Details != "Upgrade to 1.1" {
		t.Errorf("remediation = %+v", rem)
	}
	if len(rem.ProductIDs) != 1 || rem.ProductIDs[0] != "CSAFPID-1" {
		t.Errorf("remediation product_ids = %v", rem.ProductIDs)
	}
}

func TestMap_IsDeterministicAcrossCalls(t *testing.T) {
	doc, err := ParseDocument([]byte(validCSAF))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	m1, err := Map(doc, "opencsirt")
	if err != nil {
		t.Fatalf("map 1: %v", err)
	}
	m2, err := Map(doc, "opencsirt")
	if err != nil {
		t.Fatalf("map 2: %v", err)
	}
	if m1.StixObjects[0].StixID != m2.StixObjects[0].StixID {
		t.Errorf("stix id not deterministic: %q vs %q", m1.StixObjects[0].StixID, m2.StixObjects[0].StixID)
	}
	if m1.StixBundleID != m2.StixBundleID {
		t.Errorf("bundle id not deterministic: %q vs %q", m1.StixBundleID, m2.StixBundleID)
	}
}

func TestMap_DifferentRevisionsProduceDifferentStixIDs(t *testing.T) {
	doc, err := ParseDocument([]byte(validCSAF))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	m1, err := Map(doc, "opencsirt")
	if err != nil {
		t.Fatalf("map v1: %v", err)
	}
	doc.Document.Tracking.Version = "2"
	m2, err := Map(doc, "opencsirt")
	if err != nil {
		t.Fatalf("map v2: %v", err)
	}
	if m1.StixObjects[0].StixID == m2.StixObjects[0].StixID {
		t.Errorf("expected different stix ids across revisions, both = %q", m1.StixObjects[0].StixID)
	}
}

func TestMap_HandlesMissingCVEWithIndexFallback(t *testing.T) {
	doc, err := ParseDocument([]byte(validCSAF))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	doc.Vulnerabilities[0].CVE = ""
	mapped, err := Map(doc, "opencsirt")
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if len(mapped.StixObjects) != 1 {
		t.Fatalf("want 1 stix object even without a CVE, got %d", len(mapped.StixObjects))
	}
	if mapped.Vulnerabilities[0].CVE != "" {
		t.Errorf("cve should stay empty, got %q", mapped.Vulnerabilities[0].CVE)
	}
}
