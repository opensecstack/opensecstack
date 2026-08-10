package main

// snapshotRulesAdapter's MemoryRepo fallback path (CountByType /
// V4V6Split walking a.repo.List) is real, testable logic — it runs
// whenever OPENSCRUB_DB_URL is unset (dev mode). Every other adapter
// in main.go is a thin wrapper around a *db.X concrete type and needs
// a live Postgres to exercise, which is out of scope here (see
// internal/db package doc comment — those tests skip without
// OPENSCRUB_TEST_DB_URL). This one doesn't need that: newSnapshotRulesAdapter
// only wires the SQL-aggregate path when its repo argument is
// concretely a *db.RuleStore, so passing a *rules.MemoryRepo exercises
// the walking fallback in-process.

import (
	"context"
	"testing"

	"github.com/opensecstack/openscrub/internal/rules"
)

func TestSnapshotRulesAdapterCountByTypeWalksMemoryRepo(t *testing.T) {
	repo := rules.NewMemoryRepo()
	ctx := context.Background()
	seed := []rules.Rule{
		{Type: rules.TypeBlocklist, CIDR: "203.0.113.0/24", TTLSeconds: 60, Source: rules.SourceOperator},
		{Type: rules.TypeBlocklist, CIDR: "198.51.100.0/24", TTLSeconds: 60, Source: rules.SourceOperator},
		{Type: rules.TypeRatelimit, CIDR: "192.0.2.1/32", TTLSeconds: 60, Source: rules.SourceOperator},
	}
	for _, r := range seed {
		if _, err := repo.Insert(ctx, r); err != nil {
			t.Fatalf("seed insert: %v", err)
		}
	}
	port := 443
	if _, err := repo.Insert(ctx, rules.Rule{Type: rules.TypeSynCookie, Port: &port, TTLSeconds: 60}); err != nil {
		t.Fatalf("seed syncookie insert: %v", err)
	}

	a := newSnapshotRulesAdapter(repo)
	bl, rl, sc, err := a.CountByType(ctx)
	if err != nil {
		t.Fatalf("CountByType: %v", err)
	}
	if bl != 2 || rl != 1 || sc != 1 {
		t.Fatalf("CountByType = (bl=%d, rl=%d, sc=%d), want (2, 1, 1)", bl, rl, sc)
	}
}

func TestSnapshotRulesAdapterV4V6SplitWalksMemoryRepo(t *testing.T) {
	repo := rules.NewMemoryRepo()
	ctx := context.Background()
	seed := []rules.Rule{
		{Type: rules.TypeBlocklist, CIDR: "203.0.113.0/24", TTLSeconds: 60},
		{Type: rules.TypeBlocklist, CIDR: "198.51.100.0/24", TTLSeconds: 60},
		{Type: rules.TypeBlocklist, CIDR: "2001:db8::/32", TTLSeconds: 60},
		// Non-blocklist rules must be excluded from the split entirely.
		{Type: rules.TypeRatelimit, CIDR: "192.0.2.1/32", TTLSeconds: 60},
	}
	for _, r := range seed {
		if _, err := repo.Insert(ctx, r); err != nil {
			t.Fatalf("seed insert %q: %v", r.CIDR, err)
		}
	}

	a := newSnapshotRulesAdapter(repo)
	v4, v6, err := a.V4V6Split(ctx)
	if err != nil {
		t.Fatalf("V4V6Split: %v", err)
	}
	if v4 != 2 || v6 != 1 {
		t.Fatalf("V4V6Split = (v4=%d, v6=%d), want (2, 1)", v4, v6)
	}
}

func TestSnapshotRulesAdapterCountByTypeEmptyRepo(t *testing.T) {
	a := newSnapshotRulesAdapter(rules.NewMemoryRepo())
	bl, rl, sc, err := a.CountByType(context.Background())
	if err != nil {
		t.Fatalf("CountByType: %v", err)
	}
	if bl != 0 || rl != 0 || sc != 0 {
		t.Fatalf("CountByType on empty repo = (%d,%d,%d), want zeros", bl, rl, sc)
	}
}
