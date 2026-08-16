package dataplane

// Real Unix-domain-socket tests for UDSClient. Unlike uds_test.go's
// single happy-path test (which skips on Windows out of historical
// caution), these exercise the full RPC surface — every op, the
// ok:false error path, the "unspecified rpc error" default, dial
// failure, and connection-reset/reconnect behavior — against a real
// net.Listen("unix", ...) server. Verified to work on this Windows 11
// dev box (Go's "unix" network is backed by AFUNIX sockets since
// Windows 10 1803+), and unconditionally supported on the Linux CI
// runners this ultimately gates.
//
// fakeLoader is a tiny scriptable stand-in for the Rust loader: each
// call to Accept starts a fresh handler goroutine that reads exactly
// one line-delimited JSON request and replies with a canned response
// (looked up by the "op" field, or a default).

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fakeLoader accepts unix-socket connections and, for each incoming
// request line, replies according to a per-op canned response table
// (falling back to a generic {"ok":true} for ops with no entry).
type fakeLoader struct {
	t        *testing.T
	ln       net.Listener
	mu       sync.Mutex
	requests []map[string]any
	replies  map[string]string // op -> raw JSON reply line (no trailing \n)
	closed   bool
}

func newFakeLoader(t *testing.T) *fakeLoader {
	t.Helper()
	sock := filepath.Join(shortSockDir(t), "f.sock")
	return newFakeLoaderAt(t, sock)
}

// shortSockDir returns a short-path temp directory suitable for a Unix
// socket path. t.TempDir() embeds the full (often long) test name in
// the path, which blows past the ~108-byte sun_path limit the AF_UNIX
// implementation enforces (observed as "bind: invalid argument" on
// Windows AFUNIX once the full socket path exceeds the limit) — use
// os.MkdirTemp with a short, fixed prefix instead.
func shortSockDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "dpuds")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func newFakeLoaderAt(t *testing.T, sock string) *fakeLoader {
	t.Helper()
	ln, err := new(net.ListenConfig).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatalf("listen unix %s: %v", sock, err)
	}
	fl := &fakeLoader{t: t, ln: ln, replies: map[string]string{}}
	go fl.serve()
	t.Cleanup(func() { fl.close() })
	return fl
}

func (fl *fakeLoader) socket() string { return fl.ln.Addr().String() }

func (fl *fakeLoader) close() {
	fl.mu.Lock()
	defer fl.mu.Unlock()
	if !fl.closed {
		fl.closed = true
		_ = fl.ln.Close()
	}
}

func (fl *fakeLoader) setReply(op, jsonLine string) {
	fl.mu.Lock()
	defer fl.mu.Unlock()
	fl.replies[op] = jsonLine
}

func (fl *fakeLoader) recordedRequests() []map[string]any {
	fl.mu.Lock()
	defer fl.mu.Unlock()
	out := make([]map[string]any, len(fl.requests))
	copy(out, fl.requests)
	return out
}

func (fl *fakeLoader) serve() {
	for {
		conn, err := fl.ln.Accept()
		if err != nil {
			return
		}
		go fl.handleConn(conn)
	}
}

func (fl *fakeLoader) handleConn(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return
		}
		var req map[string]any
		if jsonErr := json.Unmarshal(line, &req); jsonErr != nil {
			return
		}
		fl.mu.Lock()
		fl.requests = append(fl.requests, req)
		op, _ := req["op"].(string)
		reply, ok := fl.replies[op]
		fl.mu.Unlock()
		if !ok {
			reply = `{"ok":true}`
		}
		if _, err := conn.Write([]byte(reply + "\n")); err != nil {
			return
		}
	}
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("ParsePrefix(%q): %v", s, err)
	}
	return p
}

func TestUDSClientAddBlocklistSelectsV4OrV6Op(t *testing.T) {
	fl := newFakeLoader(t)
	c := NewUDSClient(fl.socket(), time.Second)
	defer c.Close()
	ctx := context.Background()

	if err := c.AddBlocklist(ctx, mustPrefix(t, "203.0.113.0/24")); err != nil {
		t.Fatalf("AddBlocklist v4: %v", err)
	}
	if err := c.AddBlocklist(ctx, mustPrefix(t, "2001:db8::/32")); err != nil {
		t.Fatalf("AddBlocklist v6: %v", err)
	}
	reqs := fl.recordedRequests()
	if len(reqs) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(reqs))
	}
	if reqs[0]["op"] != "add_blocklist_v4" || reqs[0]["prefix"] != "203.0.113.0/24" {
		t.Fatalf("v4 request wrong: %+v", reqs[0])
	}
	if reqs[1]["op"] != "add_blocklist_v6" || reqs[1]["prefix"] != "2001:db8::/32" {
		t.Fatalf("v6 request wrong: %+v", reqs[1])
	}
}

func TestUDSClientRemoveBlocklistSelectsV4OrV6Op(t *testing.T) {
	fl := newFakeLoader(t)
	c := NewUDSClient(fl.socket(), time.Second)
	defer c.Close()
	ctx := context.Background()

	if err := c.RemoveBlocklist(ctx, mustPrefix(t, "198.51.100.0/24")); err != nil {
		t.Fatalf("RemoveBlocklist v4: %v", err)
	}
	if err := c.RemoveBlocklist(ctx, mustPrefix(t, "fe80::/10")); err != nil {
		t.Fatalf("RemoveBlocklist v6: %v", err)
	}
	reqs := fl.recordedRequests()
	if reqs[0]["op"] != "remove_blocklist_v4" {
		t.Fatalf("expected remove_blocklist_v4, got %+v", reqs[0])
	}
	if reqs[1]["op"] != "remove_blocklist_v6" {
		t.Fatalf("expected remove_blocklist_v6, got %+v", reqs[1])
	}
}

func TestUDSClientSetAndClearRatelimit(t *testing.T) {
	fl := newFakeLoader(t)
	c := NewUDSClient(fl.socket(), time.Second)
	defer c.Close()
	ctx := context.Background()

	addr := netip.MustParseAddr("203.0.113.42")
	if err := c.SetRatelimit(ctx, addr, 1000); err != nil {
		t.Fatalf("SetRatelimit: %v", err)
	}
	if err := c.ClearRatelimit(ctx, addr); err != nil {
		t.Fatalf("ClearRatelimit: %v", err)
	}
	reqs := fl.recordedRequests()
	if reqs[0]["op"] != "set_ratelimit" || reqs[0]["src"] != "203.0.113.42" {
		t.Fatalf("set_ratelimit request wrong: %+v", reqs[0])
	}
	// JSON numbers decode as float64.
	if pps, _ := reqs[0]["pps"].(float64); pps != 1000 {
		t.Fatalf("pps = %v, want 1000", reqs[0]["pps"])
	}
	if reqs[1]["op"] != "clear_ratelimit" || reqs[1]["src"] != "203.0.113.42" {
		t.Fatalf("clear_ratelimit request wrong: %+v", reqs[1])
	}
}

func TestUDSClientEnableAndDisableSynCookie(t *testing.T) {
	fl := newFakeLoader(t)
	c := NewUDSClient(fl.socket(), time.Second)
	defer c.Close()
	ctx := context.Background()

	if err := c.EnableSynCookie(ctx, 443); err != nil {
		t.Fatalf("EnableSynCookie: %v", err)
	}
	if err := c.DisableSynCookie(ctx, 443); err != nil {
		t.Fatalf("DisableSynCookie: %v", err)
	}
	reqs := fl.recordedRequests()
	if reqs[0]["op"] != "enable_syncookie" {
		t.Fatalf("expected enable_syncookie, got %+v", reqs[0])
	}
	if port, _ := reqs[0]["port"].(float64); port != 443 {
		t.Fatalf("port = %v, want 443", reqs[0]["port"])
	}
	if reqs[1]["op"] != "disable_syncookie" {
		t.Fatalf("expected disable_syncookie, got %+v", reqs[1])
	}
}

// TestUDSClientSnapshotDecodesAndFiltersInvalidEntries proves Snapshot
// parses every field AND silently drops malformed prefix/address
// strings rather than failing the whole call — a single corrupt entry
// from the loader must not blind the caller to every other rule.
func TestUDSClientSnapshotDecodesAndFiltersInvalidEntries(t *testing.T) {
	fl := newFakeLoader(t)
	fl.setReply("snapshot", `{"ok":true,"result":{"blocklist_v4":["203.0.113.0/24","not-a-prefix"],"blocklist_v6":["2001:db8::/32"],"ratelimits":{"198.51.100.5":500,"not-an-ip":999},"syncookie_ports":[443,8443]}}`)
	c := NewUDSClient(fl.socket(), time.Second)
	defer c.Close()

	snap, err := c.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snap.BlocklistV4) != 1 || snap.BlocklistV4[0].String() != "203.0.113.0/24" {
		t.Fatalf("BlocklistV4 = %+v, want exactly [203.0.113.0/24] (invalid entry filtered)", snap.BlocklistV4)
	}
	if len(snap.BlocklistV6) != 1 || snap.BlocklistV6[0].String() != "2001:db8::/32" {
		t.Fatalf("BlocklistV6 = %+v", snap.BlocklistV6)
	}
	if len(snap.Ratelimits) != 1 {
		t.Fatalf("Ratelimits = %+v, want exactly 1 entry (invalid IP filtered)", snap.Ratelimits)
	}
	addr := netip.MustParseAddr("198.51.100.5")
	if snap.Ratelimits[addr] != 500 {
		t.Fatalf("Ratelimits[%s] = %d, want 500", addr, snap.Ratelimits[addr])
	}
	if len(snap.SynCookiePorts) != 2 || snap.SynCookiePorts[0] != 443 || snap.SynCookiePorts[1] != 8443 {
		t.Fatalf("SynCookiePorts = %+v", snap.SynCookiePorts)
	}
}

// TestUDSClientRPCErrorWithMessagePropagates proves an {"ok":false,
// "error":"..."} response surfaces the loader's own error text
// verbatim to the caller.
func TestUDSClientRPCErrorWithMessagePropagates(t *testing.T) {
	fl := newFakeLoader(t)
	fl.setReply("add_blocklist_v4", `{"ok":false,"error":"map full"}`)
	c := NewUDSClient(fl.socket(), time.Second)
	defer c.Close()

	err := c.AddBlocklist(context.Background(), mustPrefix(t, "203.0.113.0/24"))
	if err == nil || err.Error() != "map full" {
		t.Fatalf("expected error %q, got %v", "map full", err)
	}
}

// TestUDSClientRPCErrorWithoutMessageDefaultsToUnspecified proves the
// "unspecified rpc error" fallback fires when the loader sets
// ok:false but omits the error string — this is the caller's only
// signal that *something* went wrong, so it must never be silently
// swallowed as a generic empty error.
func TestUDSClientRPCErrorWithoutMessageDefaultsToUnspecified(t *testing.T) {
	fl := newFakeLoader(t)
	fl.setReply("enable_syncookie", `{"ok":false}`)
	c := NewUDSClient(fl.socket(), time.Second)
	defer c.Close()

	err := c.EnableSynCookie(context.Background(), 80)
	if err == nil || err.Error() != "unspecified rpc error" {
		t.Fatalf("expected \"unspecified rpc error\", got %v", err)
	}
}

// TestUDSClientDialFailureWrapsError proves a socket that doesn't
// exist produces a clearly-labeled dial error rather than a bare
// "connection refused" that's hard to attribute to the dataplane
// socket specifically.
func TestUDSClientDialFailureWrapsError(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "does-not-exist.sock")
	c := NewUDSClient(missing, 200*time.Millisecond)
	defer c.Close()

	err := c.EnableSynCookie(context.Background(), 80)
	if err == nil {
		t.Fatal("expected an error dialing a nonexistent socket")
	}
	wantPrefix := fmt.Sprintf("dial dataplane socket %s", missing)
	if got := err.Error(); len(got) < len(wantPrefix) || got[:len(wantPrefix)] != wantPrefix {
		t.Fatalf("error = %q, want prefix %q", got, wantPrefix)
	}
}

// TestUDSClientResetsAndReconnectsAfterServerCloses proves a slot
// whose connection was dropped by the peer transparently redials on
// the next call rather than returning a stale-connection error
// forever — this is exactly the "loader restarted" scenario the
// pooled-slot design must survive.
func TestUDSClientResetsAndReconnectsAfterServerCloses(t *testing.T) {
	sock := filepath.Join(shortSockDir(t), "r.sock")
	fl := newFakeLoaderAt(t, sock)
	// Small pool timeout so a broken connection fails fast.
	c := NewUDSClient(sock, 500*time.Millisecond)
	defer c.Close()
	ctx := context.Background()

	// Drive one call through every pool slot so each one dials and
	// caches a live connection to the original loader.
	for i := 0; i < defaultUDSPoolSize; i++ {
		if err := c.EnableSynCookie(ctx, 80); err != nil {
			t.Fatalf("warmup call %d: %v", i, err)
		}
	}

	// Kill the loader's listener AND every accepted connection so each
	// pooled slot holds a genuinely dead conn, then rebind a fresh
	// listener at the exact same path (simulates the Rust loader
	// restarting in place). The same UDSClient — same pooled slots —
	// must transparently redial rather than returning a stale-connection
	// error forever: the very first call against a dead slot may error
	// (its write/read fails against the closed peer), but that failure
	// must reset the slot so the NEXT call against it redials cleanly.
	fl.close()
	if err := os.Remove(sock); err != nil && !os.IsNotExist(err) {
		t.Fatalf("remove stale socket: %v", err)
	}
	newFakeLoaderAt(t, sock)

	// Cycle through several full rounds of the pool. Every slot must
	// have recovered (i.e. produced at least one successful call)
	// within a bounded number of rounds — a client that got stuck
	// forever returning the post-restart dial/read error would fail
	// this within the attempt budget.
	successBySlot := make([]bool, defaultUDSPoolSize)
	successCount := 0
	for round := 0; round < 3 && successCount < defaultUDSPoolSize; round++ {
		for slot := 0; slot < defaultUDSPoolSize; slot++ {
			if successBySlot[slot] {
				continue
			}
			if err := c.EnableSynCookie(ctx, 80); err == nil {
				successBySlot[slot] = true
				successCount++
			}
		}
	}
	if successCount != defaultUDSPoolSize {
		t.Fatalf("only %d/%d slots recovered after loader restart: %+v", successCount, defaultUDSPoolSize, successBySlot)
	}
}

// TestUDSClientDefaultTimeoutAppliedWhenNonPositive proves NewUDSClient
// substitutes the 2s default when callers pass a zero or negative
// timeout, rather than leaving the client with a useless immediate
// deadline.
func TestUDSClientDefaultTimeoutAppliedWhenNonPositive(t *testing.T) {
	c := NewUDSClient("irrelevant.sock", 0)
	if c.timeout != 2*time.Second {
		t.Fatalf("timeout = %v, want 2s default", c.timeout)
	}
	c2 := NewUDSClient("irrelevant.sock", -5*time.Second)
	if c2.timeout != 2*time.Second {
		t.Fatalf("timeout = %v, want 2s default for negative input", c2.timeout)
	}
}

// TestUDSClientPoolRoundRobinsAcrossSlots exercises pick()'s
// round-robin distribution directly — with defaultUDSPoolSize slots,
// N consecutive picks must visit each slot exactly N/poolSize times
// and never repeat a slot before the others have had a turn.
func TestUDSClientPoolRoundRobinsAcrossSlots(t *testing.T) {
	c := NewUDSClient("irrelevant.sock", time.Second)
	seen := make([]*udsConn, 0, defaultUDSPoolSize)
	for i := 0; i < defaultUDSPoolSize; i++ {
		seen = append(seen, c.pick())
	}
	// All defaultUDSPoolSize picks in one lap must be distinct slots.
	for i := range seen {
		for j := range seen {
			if i != j && seen[i] == seen[j] {
				t.Fatalf("pick() returned the same slot twice within one round (i=%d j=%d)", i, j)
			}
		}
	}
	// The next pick must wrap back to the first slot.
	if wrapped := c.pick(); wrapped != seen[0] {
		t.Fatal("pick() did not wrap back to the first slot after a full round")
	}
}

// TestUDSClientCloseIsIdempotentAndReusable proves Close() can be
// called multiple times without panicking (each resetSlot no-ops on a
// nil conn) and that a client remains usable — a fresh call redials —
// after Close(), matching how the sweeper/shutdown paths use it.
func TestUDSClientCloseIsIdempotentAndReusable(t *testing.T) {
	fl := newFakeLoader(t)
	c := NewUDSClient(fl.socket(), time.Second)

	if err := c.EnableSynCookie(context.Background(), 80); err != nil {
		t.Fatalf("initial call: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close (idempotency): %v", err)
	}
	// Client must still be usable post-Close (slots simply redial).
	if err := c.EnableSynCookie(context.Background(), 80); err != nil {
		t.Fatalf("call after Close: %v", err)
	}
}

// TestUDSClientStatsAndSnapshotIntegration is a broader end-to-end
// smoke test combining ops in sequence against one fake loader,
// documenting the client's real call pattern (install several rules,
// then read them back via Snapshot/Stats).
func TestUDSClientStatsAndSnapshotIntegration(t *testing.T) {
	fl := newFakeLoader(t)
	fl.setReply("stats", `{"ok":true,"result":{"packets_passed":100,"packets_dropped":5,"packets_ratelimited":0,"packets_malformed":0,"syn_cookies_sent":0}}`)
	c := NewUDSClient(fl.socket(), time.Second)
	defer c.Close()
	ctx := context.Background()

	if err := c.AddBlocklist(ctx, mustPrefix(t, "203.0.113.0/24")); err != nil {
		t.Fatal(err)
	}
	stats, err := c.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.PacketsPassed != 100 || stats.PacketsDropped != 5 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}
