//go:build integration

package store

import (
	"context"
	"testing"
)

func TestIntegration_IOCUpsert_DeduplicatesByPatternHash(t *testing.T) {
	pool := testDB(t)
	s := NewIOCStore(pool)
	ctx := context.Background()

	ioc1 := &IOC{
		Type: "ipv4-addr", Value: "1.2.3.4",
		Pattern: "[ipv4-addr:value = '1.2.3.4']",
		Source:  "feed-a", Confidence: 60,
		Tags: []string{"c2"},
	}
	mustOK(t, s.Upsert(ctx, ioc1), "upsert 1")

	// Second call with same pattern but higher confidence and new tag
	ioc2 := &IOC{
		Type: "ipv4-addr", Value: "1.2.3.4",
		Pattern: "[ipv4-addr:value = '1.2.3.4']",
		Source:  "feed-b", Confidence: 90,
		Tags: []string{"malware"},
	}
	mustOK(t, s.Upsert(ctx, ioc2), "upsert 2")
	if ioc1.ID != ioc2.ID {
		t.Errorf("expected same ID (dedup), got %s vs %s", ioc1.ID, ioc2.ID)
	}

	got, err := s.Get(ctx, ioc1.ID)
	mustOK(t, err, "get")
	if got.Confidence != 90 {
		t.Errorf("confidence should be max(60,90)=90, got %d", got.Confidence)
	}
	if len(got.Tags) != 2 {
		t.Errorf("tags should be merged to [c2, malware], got %v", got.Tags)
	}
}

func TestIntegration_IOCList_FiltersByType(t *testing.T) {
	pool := testDB(t)
	s := NewIOCStore(pool)
	ctx := context.Background()

	// Seed 3 domains, 2 ipv4s
	for i, v := range []string{"a.example", "b.example", "c.example"} {
		mustOK(t, s.Upsert(ctx, &IOC{
			Type: "domain-name", Value: v,
			Pattern: "[domain-name:value = '" + v + "']",
			Confidence: 50 + i,
		}), "seed domain")
	}
	for _, v := range []string{"1.1.1.1", "2.2.2.2"} {
		mustOK(t, s.Upsert(ctx, &IOC{
			Type: "ipv4-addr", Value: v,
			Pattern: "[ipv4-addr:value = '" + v + "']",
			Confidence: 70,
		}), "seed ipv4")
	}

	items, total, err := s.List(ctx, IOCFilter{Type: "domain-name"})
	mustOK(t, err, "list")
	if total != 3 {
		t.Errorf("total domains = %d, want 3", total)
	}
	if len(items) != 3 {
		t.Errorf("rows = %d, want 3", len(items))
	}
}

func TestIntegration_IOCByValue(t *testing.T) {
	pool := testDB(t)
	s := NewIOCStore(pool)
	ctx := context.Background()

	mustOK(t, s.Upsert(ctx, &IOC{
		Type: "domain-name", Value: "lookup.example",
		Pattern: "[domain-name:value = 'lookup.example']",
		Confidence: 75,
	}), "seed")

	got, err := s.IOCByValue(ctx, "domain-name", "lookup.example")
	mustOK(t, err, "lookup")
	if got.Value != "lookup.example" {
		t.Errorf("value = %q", got.Value)
	}

	if _, err := s.IOCByValue(ctx, "domain-name", "unknown.example"); err != ErrNotFound {
		t.Errorf("want ErrNotFound for unknown, got %v", err)
	}
}

func TestIntegration_IOCRevoke_MarksSoftDeleted(t *testing.T) {
	pool := testDB(t)
	s := NewIOCStore(pool)
	ctx := context.Background()

	ioc := &IOC{
		Type: "url", Value: "http://stale.example",
		Pattern:    "[url:value = 'http://stale.example']",
		Confidence: 50,
	}
	mustOK(t, s.Upsert(ctx, ioc), "seed")
	mustOK(t, s.Revoke(ctx, ioc.ID), "revoke")

	got, err := s.Get(ctx, ioc.ID)
	mustOK(t, err, "get after revoke")
	if !got.Revoked {
		t.Error("expected Revoked=true")
	}
	// IOCByValue should skip revoked rows
	if _, err := s.IOCByValue(ctx, "url", "http://stale.example"); err != ErrNotFound {
		t.Errorf("IOCByValue should skip revoked, got %v", err)
	}
}
