package stix

import (
	"errors"
	"strings"
	"testing"
)

const minimalBundle = `{
  "type": "bundle",
  "id": "bundle--44444444-4444-4444-4444-444444444444",
  "spec_version": "2.1",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--11111111-1111-1111-1111-111111111111",
      "created": "2026-01-01T00:00:00Z",
      "modified": "2026-01-01T00:00:00Z",
      "pattern_type": "stix",
      "pattern": "[ipv4-addr:value = '1.2.3.4']",
      "valid_from": "2026-01-01T00:00:00Z",
      "indicator_types": ["malicious-activity"],
      "confidence": 80,
      "labels": ["c2"]
    }
  ]
}`

func TestParseBundle_Valid(t *testing.T) {
	b, err := ParseBundle([]byte(minimalBundle))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if b.Type != "bundle" {
		t.Errorf("type = %q", b.Type)
	}
	if !strings.HasPrefix(b.ID, "bundle--") {
		t.Errorf("id = %q", b.ID)
	}
}

func TestParseBundle_RejectsNonBundle(t *testing.T) {
	bad := `{"type":"indicator","id":"indicator--00000000-0000-0000-0000-000000000000","objects":[]}`
	_, err := ParseBundle([]byte(bad))
	if !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("want ErrInvalidBundle, got %v", err)
	}
}

func TestParseBundle_RejectsBadID(t *testing.T) {
	bad := `{"type":"bundle","id":"bundle--nope","objects":[{}]}`
	_, err := ParseBundle([]byte(bad))
	if !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("want ErrInvalidBundle, got %v", err)
	}
}

func TestDecodeObjects_ExtractsIndicator(t *testing.T) {
	b, err := ParseBundle([]byte(minimalBundle))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	objs, err := DecodeObjects(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(objs) != 1 {
		t.Fatalf("want 1 object, got %d", len(objs))
	}
	ind, ok, err := AsIndicator(objs[0])
	if err != nil || !ok {
		t.Fatalf("AsIndicator: ok=%v err=%v", ok, err)
	}
	if ind.Pattern != "[ipv4-addr:value = '1.2.3.4']" {
		t.Errorf("pattern = %q", ind.Pattern)
	}
	if ind.Confidence != 80 {
		t.Errorf("confidence = %d", ind.Confidence)
	}
}

const malwareBundle = `{
  "type": "bundle",
  "id": "bundle--44444444-4444-4444-4444-444444444444",
  "objects": [
    {
      "type": "malware",
      "id": "malware--22222222-2222-2222-2222-222222222222",
      "name": "Emotet",
      "malware_types": ["trojan"],
      "is_family": true
    },
    {
      "type": "attack-pattern",
      "id": "attack-pattern--33333333-3333-3333-3333-333333333333",
      "name": "Phishing",
      "kill_chain_phases": [{"kill_chain_name":"mitre-attack","phase_name":"initial-access"}]
    },
    {
      "type": "relationship",
      "id": "relationship--55555555-5555-5555-5555-555555555555",
      "relationship_type": "uses",
      "source_ref": "malware--22222222-2222-2222-2222-222222222222",
      "target_ref": "attack-pattern--33333333-3333-3333-3333-333333333333"
    },
    {
      "type": "vulnerability",
      "id": "vulnerability--66666666-6666-6666-6666-666666666666",
      "name": "CVE-2026-0001",
      "external_references": [{"source_name":"cve","external_id":"CVE-2026-0001"}]
    }
  ]
}`

func TestAsMalware_DecodesMatchingType(t *testing.T) {
	b, err := ParseBundle([]byte(malwareBundle))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	objs, err := DecodeObjects(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	m, ok, err := AsMalware(objs[0])
	if err != nil || !ok {
		t.Fatalf("AsMalware: ok=%v err=%v", ok, err)
	}
	if m.Name != "Emotet" {
		t.Errorf("name = %q, want Emotet", m.Name)
	}
	if !m.IsFamily {
		t.Error("expected IsFamily true")
	}
	if len(m.MalwareTypes) != 1 || m.MalwareTypes[0] != "trojan" {
		t.Errorf("malware_types = %v", m.MalwareTypes)
	}
}

func TestAsMalware_FalseForNonMalwareType(t *testing.T) {
	b, _ := ParseBundle([]byte(malwareBundle))
	objs, _ := DecodeObjects(b)
	_, ok, err := AsMalware(objs[1]) // attack-pattern
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false for non-malware object")
	}
}

func TestAsAttackPattern_DecodesMatchingType(t *testing.T) {
	b, _ := ParseBundle([]byte(malwareBundle))
	objs, err := DecodeObjects(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	ap, ok, err := AsAttackPattern(objs[1])
	if err != nil || !ok {
		t.Fatalf("AsAttackPattern: ok=%v err=%v", ok, err)
	}
	if ap.Name != "Phishing" {
		t.Errorf("name = %q, want Phishing", ap.Name)
	}
	if len(ap.KillChain) != 1 || ap.KillChain[0].PhaseName != "initial-access" {
		t.Errorf("kill chain = %+v", ap.KillChain)
	}
}

func TestAsAttackPattern_FalseForNonMatchingType(t *testing.T) {
	b, _ := ParseBundle([]byte(malwareBundle))
	objs, _ := DecodeObjects(b)
	_, ok, err := AsAttackPattern(objs[0]) // malware
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false for non-attack-pattern object")
	}
}

func TestAsRelationship_DecodesMatchingType(t *testing.T) {
	b, _ := ParseBundle([]byte(malwareBundle))
	objs, err := DecodeObjects(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	rel, ok, err := AsRelationship(objs[2])
	if err != nil || !ok {
		t.Fatalf("AsRelationship: ok=%v err=%v", ok, err)
	}
	if rel.RelationshipType != "uses" {
		t.Errorf("relationship_type = %q, want uses", rel.RelationshipType)
	}
	if rel.SourceRef != "malware--22222222-2222-2222-2222-222222222222" {
		t.Errorf("source_ref = %q", rel.SourceRef)
	}
	if rel.TargetRef != "attack-pattern--33333333-3333-3333-3333-333333333333" {
		t.Errorf("target_ref = %q", rel.TargetRef)
	}
}

func TestAsRelationship_FalseForNonMatchingType(t *testing.T) {
	b, _ := ParseBundle([]byte(malwareBundle))
	objs, _ := DecodeObjects(b)
	_, ok, err := AsRelationship(objs[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false for non-relationship object")
	}
}

func TestAsVulnerability_DecodesMatchingType(t *testing.T) {
	b, _ := ParseBundle([]byte(malwareBundle))
	objs, err := DecodeObjects(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	v, ok, err := AsVulnerability(objs[3])
	if err != nil || !ok {
		t.Fatalf("AsVulnerability: ok=%v err=%v", ok, err)
	}
	if v.Name != "CVE-2026-0001" {
		t.Errorf("name = %q, want CVE-2026-0001", v.Name)
	}
	if len(v.ExternalRefs) != 1 || v.ExternalRefs[0].ExternalID != "CVE-2026-0001" {
		t.Errorf("external refs = %+v", v.ExternalRefs)
	}
}

func TestAsVulnerability_FalseForNonMatchingType(t *testing.T) {
	b, _ := ParseBundle([]byte(malwareBundle))
	objs, _ := DecodeObjects(b)
	_, ok, err := AsVulnerability(objs[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false for non-vulnerability object")
	}
}

func TestDecodeObjects_RejectsMismatchedIDPrefix(t *testing.T) {
	bad := `{
      "type": "bundle",
      "id": "bundle--44444444-4444-4444-4444-444444444444",
      "objects": [{"type":"indicator","id":"malware--11111111-1111-1111-1111-111111111111"}]
    }`
	b, err := ParseBundle([]byte(bad))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := DecodeObjects(b); err == nil {
		t.Fatal("expected id-prefix error")
	}
}
