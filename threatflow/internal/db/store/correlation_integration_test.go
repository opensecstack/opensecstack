//go:build integration

package store

import (
	"context"
	"encoding/json"
	"testing"
)

func TestIntegration_Correlation_UpsertAndForIOC(t *testing.T) {
	pool := testDB(t)
	iocs := NewIOCStore(pool)
	corr := NewCorrelationStore(pool)
	ctx := context.Background()

	a := &IOC{Type: "domain-name", Value: "a.example", Pattern: "[domain-name:value = 'a.example']", Confidence: 60}
	b := &IOC{Type: "domain-name", Value: "login.a.example", Pattern: "[domain-name:value = 'login.a.example']", Confidence: 70}
	mustOK(t, iocs.Upsert(ctx, a), "seed a")
	mustOK(t, iocs.Upsert(ctx, b), "seed b")

	ev, _ := json.Marshal(map[string]string{"parent": "a.example", "subdomain": "login.a.example"})
	mustOK(t, corr.Upsert(ctx, &Correlation{
		SourceIOCID:  b.ID,
		TargetIOCID:  a.ID,
		Relationship: "subdomain-of",
		Confidence:   85,
		Evidence:     ev,
	}), "upsert")

	// Query from either direction
	fromB, err := corr.ForIOC(ctx, b.ID)
	mustOK(t, err, "forIOC b")
	if len(fromB) != 1 || fromB[0].Direction != "outbound" {
		t.Errorf("unexpected b correlations: %+v", fromB)
	}

	fromA, err := corr.ForIOC(ctx, a.ID)
	mustOK(t, err, "forIOC a")
	if len(fromA) != 1 || fromA[0].Direction != "inbound" {
		t.Errorf("unexpected a correlations: %+v", fromA)
	}
}

func TestIntegration_Correlation_UniqueTriple(t *testing.T) {
	pool := testDB(t)
	iocs := NewIOCStore(pool)
	corr := NewCorrelationStore(pool)
	ctx := context.Background()

	a := &IOC{Type: "ipv4-addr", Value: "10.0.0.1", Pattern: "[ipv4-addr:value = '10.0.0.1']"}
	b := &IOC{Type: "ipv4-addr", Value: "10.0.0.2", Pattern: "[ipv4-addr:value = '10.0.0.2']"}
	mustOK(t, iocs.Upsert(ctx, a), "seed a")
	mustOK(t, iocs.Upsert(ctx, b), "seed b")

	c1 := &Correlation{SourceIOCID: a.ID, TargetIOCID: b.ID, Relationship: "same-network", Confidence: 60}
	c2 := &Correlation{SourceIOCID: a.ID, TargetIOCID: b.ID, Relationship: "same-network", Confidence: 80}

	mustOK(t, corr.Upsert(ctx, c1), "first upsert")
	mustOK(t, corr.Upsert(ctx, c2), "second upsert")

	// Same row reused; confidence is max(60, 80) = 80
	var count, conf int
	row := pool.QueryRow(ctx, `SELECT count(*)::int, max(confidence)::int FROM ioc_correlations WHERE source_ioc_id = $1 AND target_ioc_id = $2 AND relationship = 'same-network'`, a.ID, b.ID)
	mustOK(t, row.Scan(&count, &conf), "scan")
	if count != 1 {
		t.Errorf("unique constraint violated, got %d rows", count)
	}
	if conf != 80 {
		t.Errorf("confidence not upgraded, got %d", conf)
	}
}
