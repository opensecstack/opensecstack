// Package dataplane is the Go-side abstraction over the Rust XDP loader.
//
// The Rust crate `openscrub_dataplane` exposes a MapWriter API
// (add/remove blocklist v4/v6, set/clear ratelimit, snapshot). Two
// transports satisfy the Client interface here:
//
//   - NoopClient — used in unit tests and on hosts without CAP_BPF.
//     All mutations are remembered in a shadow set so callers can
//     read back what they wrote (mirrors the "detached mode" of the
//     Rust MapWriter).
//   - UDSClient — line-delimited JSON RPC over a Unix-domain socket
//     (see docs/architecture.md §IPC). The Rust loader is the server;
//     this is the production transport. Chosen over CGo FFI to avoid
//     ABI lock-in — see the architecture doc for the trade-off.
//
// The interface is rule-oriented (AddBlocklist / RemoveBlocklist /
// SetRatelimit / ClearRatelimit) so handlers don't care which transport
// is configured.
package dataplane

import (
	"context"
	"net/netip"
	"sort"
	"sync"
)

// Client is the surface the rules service uses to push/pull rules to
// the data plane.
type Client interface {
	AddBlocklist(ctx context.Context, prefix netip.Prefix) error
	RemoveBlocklist(ctx context.Context, prefix netip.Prefix) error
	SetRatelimit(ctx context.Context, src netip.Addr, pps uint64) error
	ClearRatelimit(ctx context.Context, src netip.Addr) error
	// EnableSynCookie enables XDP SYN-cookie generation for the TCP
	// listener bound to `port` (mitigates SYN-flood without exhausting
	// the kernel's TCP socket table). Mirrors the Rust API
	// `MapWriter::enable_syncookie(port)`.
	EnableSynCookie(ctx context.Context, port uint16) error
	DisableSynCookie(ctx context.Context, port uint16) error
	Snapshot(ctx context.Context) (Snapshot, error)
	Stats(ctx context.Context) (Stats, error)
	Close() error
}

// Snapshot is a point-in-time view of installed rules.
type Snapshot struct {
	BlocklistV4    []netip.Prefix        `json:"blocklist_v4"`
	BlocklistV6    []netip.Prefix        `json:"blocklist_v6"`
	Ratelimits     map[netip.Addr]uint64 `json:"ratelimits"`
	SynCookiePorts []uint16              `json:"syncookie_ports"`
}

// Stats mirrors the Rust StatsReader::read() output.
type Stats struct {
	PacketsPassed      uint64 `json:"packets_passed"`
	PacketsDropped     uint64 `json:"packets_dropped"`
	PacketsRatelimited uint64 `json:"packets_ratelimited"`
	PacketsMalformed   uint64 `json:"packets_malformed"`
	// SynCookiesSent — count of XDP-generated SYN-cookie SYN/ACKs since
	// loader start. Source of truth is rust/dataplane/src/stats.rs;
	// older loaders that predate the field send 0 (decode is tolerant).
	SynCookiesSent     uint64 `json:"syn_cookies_sent"`
}

// NoopClient is a cap-less implementation safe to use in tests.
type NoopClient struct {
	mu             sync.Mutex
	blocklistV4    map[netip.Prefix]struct{}
	blocklistV6    map[netip.Prefix]struct{}
	ratelimits     map[netip.Addr]uint64
	synCookiePorts map[uint16]struct{}
	stats          Stats
}

// NewNoopClient returns a fresh in-memory client.
func NewNoopClient() *NoopClient {
	return &NoopClient{
		blocklistV4:    make(map[netip.Prefix]struct{}),
		blocklistV6:    make(map[netip.Prefix]struct{}),
		ratelimits:     make(map[netip.Addr]uint64),
		synCookiePorts: make(map[uint16]struct{}),
	}
}

// AddBlocklist records the prefix in the shadow set.
func (c *NoopClient) AddBlocklist(_ context.Context, prefix netip.Prefix) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if prefix.Addr().Is4() {
		c.blocklistV4[prefix] = struct{}{}
	} else {
		c.blocklistV6[prefix] = struct{}{}
	}
	return nil
}

// RemoveBlocklist removes prefix from the shadow set.
func (c *NoopClient) RemoveBlocklist(_ context.Context, prefix netip.Prefix) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.blocklistV4, prefix)
	delete(c.blocklistV6, prefix)
	return nil
}

// SetRatelimit records a per-source PPS cap.
func (c *NoopClient) SetRatelimit(_ context.Context, src netip.Addr, pps uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ratelimits[src] = pps
	return nil
}

// ClearRatelimit removes a per-source PPS cap.
func (c *NoopClient) ClearRatelimit(_ context.Context, src netip.Addr) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.ratelimits, src)
	return nil
}

// EnableSynCookie marks the port as syncookie-protected.
func (c *NoopClient) EnableSynCookie(_ context.Context, port uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.synCookiePorts[port] = struct{}{}
	return nil
}

// DisableSynCookie clears syncookie protection on the port.
func (c *NoopClient) DisableSynCookie(_ context.Context, port uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.synCookiePorts, port)
	return nil
}

// Snapshot returns sorted copies of the installed rules.
func (c *NoopClient) Snapshot(_ context.Context) (Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v4 := make([]netip.Prefix, 0, len(c.blocklistV4))
	for p := range c.blocklistV4 {
		v4 = append(v4, p)
	}
	sort.Slice(v4, func(i, j int) bool { return v4[i].String() < v4[j].String() })
	v6 := make([]netip.Prefix, 0, len(c.blocklistV6))
	for p := range c.blocklistV6 {
		v6 = append(v6, p)
	}
	sort.Slice(v6, func(i, j int) bool { return v6[i].String() < v6[j].String() })
	rl := make(map[netip.Addr]uint64, len(c.ratelimits))
	for k, v := range c.ratelimits {
		rl[k] = v
	}
	ports := make([]uint16, 0, len(c.synCookiePorts))
	for p := range c.synCookiePorts {
		ports = append(ports, p)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	return Snapshot{BlocklistV4: v4, BlocklistV6: v6, Ratelimits: rl, SynCookiePorts: ports}, nil
}

// Stats returns the recorded counters.
func (c *NoopClient) Stats(_ context.Context) (Stats, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats, nil
}

// SetStats is a test hook; not part of the Client interface.
func (c *NoopClient) SetStats(s Stats) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats = s
}

// Close is a no-op.
func (c *NoopClient) Close() error { return nil }
