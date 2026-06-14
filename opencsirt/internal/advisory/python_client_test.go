package advisory

import (
	"context"
	"testing"
)

func TestNoopGenerateProducesCSAFStub(t *testing.T) {
	c := NoopClient{}
	resp, err := c.Generate(context.Background(), GenerateRequest{
		Title: "Test advisory",
		TLP:   "GREEN",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if resp.CSAFID == "" {
		t.Fatal("CSAFID should be non-empty")
	}
	doc, ok := resp.Doc["document"].(map[string]any)
	if !ok {
		t.Fatal("doc.document should be present")
	}
	if doc["csaf_version"] != "2.0" {
		t.Fatalf("csaf_version: got %v want 2.0", doc["csaf_version"])
	}
}

func TestNoopGenerateRejectsEmptyTitle(t *testing.T) {
	c := NoopClient{}
	_, err := c.Generate(context.Background(), GenerateRequest{TLP: "GREEN"})
	if err == nil {
		t.Fatal("expected error for empty title")
	}
}

func TestNoopEnrichTagsAsUnenriched(t *testing.T) {
	c := NoopClient{}
	enriched, err := c.EnrichIOCs(context.Background(), []IOC{{Type: "ip", Value: "1.2.3.4"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(enriched) != 1 || enriched[0].Tags[0] != "unenriched" {
		t.Fatalf("expected unenriched tag, got %+v", enriched)
	}
}
