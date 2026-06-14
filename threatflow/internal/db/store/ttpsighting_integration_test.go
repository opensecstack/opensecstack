//go:build integration

package store

import (
	"context"
	"testing"
)

func TestIntegration_TTPStore_UpsertMany_BatchedTransaction(t *testing.T) {
	pool := testDB(t)
	iocs := NewIOCStore(pool)
	ttps := NewTTPStore(pool)
	ctx := context.Background()

	ioc := &IOC{Type: "domain-name", Value: "ttp.example", Pattern: "[domain-name:value = 'ttp.example']"}
	mustOK(t, iocs.Upsert(ctx, ioc), "seed")

	tags := []*TTPTag{
		{IOCID: ioc.ID, TechniqueID: "T1566", Source: "auto", Confidence: 70},
		{IOCID: ioc.ID, TechniqueID: "T1071", Source: "feed", Confidence: 90},
	}
	mustOK(t, ttps.UpsertMany(ctx, tags), "upsert many")

	got, err := ttps.ForIOC(ctx, ioc.ID)
	mustOK(t, err, "for ioc")
	if len(got) != 2 {
		t.Fatalf("want 2 tags, got %d", len(got))
	}
	// Ordered confidence desc — T1071 (90) first.
	if got[0].TechniqueID != "T1071" {
		t.Errorf("first should be T1071, got %s", got[0].TechniqueID)
	}

	summary, err := ttps.Summary(ctx, 10)
	mustOK(t, err, "summary")
	if len(summary) != 2 {
		t.Errorf("summary rows = %d", len(summary))
	}
}

func TestIntegration_TTPStore_FeedOverridesAuto(t *testing.T) {
	pool := testDB(t)
	iocs := NewIOCStore(pool)
	ttps := NewTTPStore(pool)
	ctx := context.Background()

	ioc := &IOC{Type: "url", Value: "http://feed-test.example", Pattern: "[url:value = 'http://feed-test.example']"}
	mustOK(t, iocs.Upsert(ctx, ioc), "seed")

	// Auto first (lower conf)
	mustOK(t, ttps.Upsert(ctx, &TTPTag{IOCID: ioc.ID, TechniqueID: "T1071", Source: "auto", Confidence: 60}), "auto")
	// Then feed (even with same conf, feed wins via CASE in Upsert)
	mustOK(t, ttps.Upsert(ctx, &TTPTag{IOCID: ioc.ID, TechniqueID: "T1071", Source: "feed", Confidence: 60}), "feed")

	row := pool.QueryRow(ctx, `SELECT source, confidence FROM ttp_tags WHERE ioc_id = $1 AND technique_id = 'T1071'`, ioc.ID)
	var source string
	var conf int
	mustOK(t, row.Scan(&source, &conf), "scan")
	if source != "feed" {
		t.Errorf("source = %q, want feed", source)
	}
}

func TestIntegration_SightingStore_CRUDAndPlatformCounts(t *testing.T) {
	pool := testDB(t)
	iocs := NewIOCStore(pool)
	sightings := NewSightingStore(pool)
	ctx := context.Background()

	ioc := &IOC{Type: "domain-name", Value: "sight.example", Pattern: "[domain-name:value = 'sight.example']"}
	mustOK(t, iocs.Upsert(ctx, ioc), "seed")

	for i, p := range []string{"apiguard", "apiguard", "irflow"} {
		mustOK(t, sightings.Create(ctx, &Sighting{
			IOCID:        ioc.ID,
			Platform:     p,
			ResourceType: "scan",
			ResourceID:   "resource-" + itoa(i),
		}), "create")
	}

	got, err := sightings.ForIOC(ctx, ioc.ID, 10)
	mustOK(t, err, "list")
	if len(got) != 3 {
		t.Errorf("sightings = %d, want 3", len(got))
	}

	counts, err := sightings.CountByPlatform(ctx)
	mustOK(t, err, "counts")
	if counts["apiguard"] != 2 || counts["irflow"] != 1 {
		t.Errorf("platform counts wrong: %+v", counts)
	}
}
