package csaf

import (
	"errors"
	"testing"
)

const validCSAF = `{
  "document": {
    "category": "csaf_security_advisory",
    "csaf_version": "2.0",
    "title": "Example RCE in Widget",
    "publisher": {
      "category": "coordinator",
      "name": "OpenCSIRT",
      "namespace": "https://csirt.example/"
    },
    "tracking": {
      "id": "OPENCSIRT-20260101-abcd1234",
      "initial_release_date": "2026-01-01T00:00:00Z",
      "current_release_date": "2026-01-01T00:00:00Z",
      "status": "final",
      "version": "1",
      "revision_history": [
        {"number": "1", "date": "2026-01-01T00:00:00Z", "summary": "Initial release"}
      ]
    },
    "distribution": {"tlp": {"label": "AMBER"}},
    "notes": [{"category": "summary", "text": "An RCE was found.", "title": "Summary"}]
  },
  "product_tree": {
    "full_product_names": [
      {"product_id": "CSAFPID-1", "name": "Widget 1.0", "cpe": "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"}
    ]
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2026-00001",
      "title": "CVE-2026-00001 — Example RCE in Widget",
      "notes": [{"category": "description", "text": "Remote code execution via crafted input."}],
      "product_status": {"known_affected": ["CSAFPID-1"]},
      "remediations": [
        {"category": "vendor_fix", "details": "Upgrade to 1.1", "product_ids": ["CSAFPID-1"], "url": "https://example/fix"}
      ],
      "references": [{"summary": "Advisory", "url": "https://example/advisory", "category": "external"}]
    }
  ]
}`

func TestParseDocument_AcceptsValidCSAF(t *testing.T) {
	doc, err := ParseDocument([]byte(validCSAF))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc.Document.Tracking.ID != "OPENCSIRT-20260101-abcd1234" {
		t.Errorf("tracking id = %q", doc.Document.Tracking.ID)
	}
	if len(doc.Vulnerabilities) != 1 {
		t.Fatalf("want 1 vulnerability, got %d", len(doc.Vulnerabilities))
	}
	if doc.Vulnerabilities[0].CVE != "CVE-2026-00001" {
		t.Errorf("cve = %q", doc.Vulnerabilities[0].CVE)
	}
}

func TestParseDocument_RejectsMalformedJSON(t *testing.T) {
	_, err := ParseDocument([]byte(`{not json`))
	if !errors.Is(err, ErrInvalidCSAF) {
		t.Fatalf("want ErrInvalidCSAF, got %v", err)
	}
}

func TestParseDocument_RejectsMissingTitle(t *testing.T) {
	doc := `{
  "document": {
    "category": "csaf_security_advisory",
    "publisher": {"category": "coordinator", "name": "OpenCSIRT", "namespace": "https://csirt.example/"},
    "tracking": {"id": "X-1", "initial_release_date": "2026-01-01T00:00:00Z", "current_release_date": "2026-01-01T00:00:00Z"},
    "distribution": {"tlp": {"label": "AMBER"}}
  }
}`
	_, err := ParseDocument([]byte(doc))
	if !errors.Is(err, ErrInvalidCSAF) {
		t.Fatalf("want ErrInvalidCSAF, got %v", err)
	}
}

func TestParseDocument_RejectsInvalidTLP(t *testing.T) {
	doc := `{
  "document": {
    "category": "csaf_security_advisory",
    "title": "T",
    "publisher": {"category": "coordinator", "name": "OpenCSIRT", "namespace": "https://csirt.example/"},
    "tracking": {"id": "X-1", "initial_release_date": "2026-01-01T00:00:00Z", "current_release_date": "2026-01-01T00:00:00Z"},
    "distribution": {"tlp": {"label": "PURPLE"}}
  }
}`
	_, err := ParseDocument([]byte(doc))
	if !errors.Is(err, ErrInvalidCSAF) {
		t.Fatalf("want ErrInvalidCSAF, got %v", err)
	}
}

func TestParseDocument_RejectsBadTrackingID(t *testing.T) {
	doc := `{
  "document": {
    "category": "csaf_security_advisory",
    "title": "T",
    "publisher": {"category": "coordinator", "name": "OpenCSIRT", "namespace": "https://csirt.example/"},
    "tracking": {"id": "bad id with spaces", "initial_release_date": "2026-01-01T00:00:00Z", "current_release_date": "2026-01-01T00:00:00Z"},
    "distribution": {"tlp": {"label": "AMBER"}}
  }
}`
	_, err := ParseDocument([]byte(doc))
	if !errors.Is(err, ErrInvalidCSAF) {
		t.Fatalf("want ErrInvalidCSAF, got %v", err)
	}
}

func TestParseDocument_RejectsVulnerabilityWithoutTitle(t *testing.T) {
	doc := `{
  "document": {
    "category": "csaf_security_advisory",
    "title": "T",
    "publisher": {"category": "coordinator", "name": "OpenCSIRT", "namespace": "https://csirt.example/"},
    "tracking": {"id": "X-1", "initial_release_date": "2026-01-01T00:00:00Z", "current_release_date": "2026-01-01T00:00:00Z"},
    "distribution": {"tlp": {"label": "AMBER"}}
  },
  "vulnerabilities": [{"cve": "CVE-2026-00001"}]
}`
	_, err := ParseDocument([]byte(doc))
	if !errors.Is(err, ErrInvalidCSAF) {
		t.Fatalf("want ErrInvalidCSAF, got %v", err)
	}
}

func TestDocument_VersionDefaultsToOne(t *testing.T) {
	doc, err := ParseDocument([]byte(validCSAF))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	doc.Document.Tracking.Version = ""
	if doc.Version() != "1" {
		t.Errorf("Version() = %q, want %q", doc.Version(), "1")
	}
}
