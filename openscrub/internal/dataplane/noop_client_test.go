package dataplane

import (
	"context"
	"net/netip"
	"testing"
)

func TestNoopClientAddRemoveBlocklistV4(t *testing.T) {
	c := NewNoopClient()
	ctx := context.Background()
	p4 := netip.MustParsePrefix("203.0.113.0/24")

	if err := c.AddBlocklist(ctx, p4); err != nil {
		t.Fatalf("AddBlocklist: %v", err)
	}
	snap, err := c.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snap.BlocklistV4) != 1 || snap.BlocklistV4[0] != p4 {
		t.Fatalf("expected [%v] in BlocklistV4, got %v", p4, snap.BlocklistV4)
	}
	if len(snap.BlocklistV6) != 0 {
		t.Fatalf("expected no v6 entries, got %v", snap.BlocklistV6)
	}

	if err := c.RemoveBlocklist(ctx, p4); err != nil {
		t.Fatalf("RemoveBlocklist: %v", err)
	}
	snap, err = c.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snap.BlocklistV4) != 0 {
		t.Fatalf("expected empty BlocklistV4 after remove, got %v", snap.BlocklistV4)
	}
}

func TestNoopClientAddBlocklistV6(t *testing.T) {
	c := NewNoopClient()
	ctx := context.Background()
	p6 := netip.MustParsePrefix("2001:db8::/32")

	if err := c.AddBlocklist(ctx, p6); err != nil {
		t.Fatalf("AddBlocklist: %v", err)
	}
	snap, err := c.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snap.BlocklistV6) != 1 || snap.BlocklistV6[0] != p6 {
		t.Fatalf("expected [%v] in BlocklistV6, got %v", p6, snap.BlocklistV6)
	}
	if len(snap.BlocklistV4) != 0 {
		t.Fatalf("expected no v4 entries, got %v", snap.BlocklistV4)
	}
}

func TestNoopClientSnapshotSortedOrder(t *testing.T) {
	c := NewNoopClient()
	ctx := context.Background()
	// Insert out of order; Snapshot must return them sorted by String().
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("198.51.100.0/24"),
	}
	for _, p := range prefixes {
		if err := c.AddBlocklist(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	snap, err := c.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0/8", "198.51.100.0/24", "203.0.113.0/24"}
	if len(snap.BlocklistV4) != len(want) {
		t.Fatalf("got %d entries, want %d", len(snap.BlocklistV4), len(want))
	}
	for i, w := range want {
		if snap.BlocklistV4[i].String() != w {
			t.Fatalf("index %d: got %s, want %s (full: %v)", i, snap.BlocklistV4[i], w, snap.BlocklistV4)
		}
	}
}

func TestNoopClientSetClearRatelimit(t *testing.T) {
	c := NewNoopClient()
	ctx := context.Background()
	addr := netip.MustParseAddr("203.0.113.5")

	if err := c.SetRatelimit(ctx, addr, 1000); err != nil {
		t.Fatalf("SetRatelimit: %v", err)
	}
	snap, err := c.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pps, ok := snap.Ratelimits[addr]; !ok || pps != 1000 {
		t.Fatalf("expected ratelimit 1000 for %v, got %v (ok=%v)", addr, pps, ok)
	}

	if err := c.ClearRatelimit(ctx, addr); err != nil {
		t.Fatalf("ClearRatelimit: %v", err)
	}
	snap, err = c.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := snap.Ratelimits[addr]; ok {
		t.Fatalf("expected ratelimit cleared, still present: %v", snap.Ratelimits)
	}
}

func TestNoopClientEnableDisableSynCookie(t *testing.T) {
	c := NewNoopClient()
	ctx := context.Background()

	if err := c.EnableSynCookie(ctx, 443); err != nil {
		t.Fatalf("EnableSynCookie: %v", err)
	}
	if err := c.EnableSynCookie(ctx, 8443); err != nil {
		t.Fatalf("EnableSynCookie: %v", err)
	}
	snap, err := c.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.SynCookiePorts) != 2 || snap.SynCookiePorts[0] != 443 || snap.SynCookiePorts[1] != 8443 {
		t.Fatalf("expected sorted [443 8443], got %v", snap.SynCookiePorts)
	}

	if err := c.DisableSynCookie(ctx, 443); err != nil {
		t.Fatalf("DisableSynCookie: %v", err)
	}
	snap, err = c.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.SynCookiePorts) != 1 || snap.SynCookiePorts[0] != 8443 {
		t.Fatalf("expected [8443] after disabling 443, got %v", snap.SynCookiePorts)
	}
}

func TestNoopClientStatsRoundTrip(t *testing.T) {
	c := NewNoopClient()
	ctx := context.Background()

	empty, err := c.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if empty != (Stats{}) {
		t.Fatalf("expected zero-value Stats before SetStats, got %+v", empty)
	}

	want := Stats{PacketsPassed: 1, PacketsDropped: 2, PacketsRatelimited: 3, PacketsMalformed: 4, SynCookiesSent: 5}
	c.SetStats(want)
	got, err := c.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if got != want {
		t.Fatalf("Stats = %+v, want %+v", got, want)
	}
}

func TestNoopClientClose(t *testing.T) {
	c := NewNoopClient()
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
