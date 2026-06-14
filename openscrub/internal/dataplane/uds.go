// UDS RPC client. Wire protocol is line-delimited JSON: each request is
// a single line {"op": "...", ...} terminated by '\n'; the server
// answers with {"ok": true} or {"ok": false, "error": "..."}.
//
// We deliberately avoid streaming / multiplex framing — the throughput
// is rule-changes-per-second, not packets-per-second.
package dataplane

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// udsConn is one connection slot — the wire protocol is line-oriented
// and not multiplexed, so a single conn can only carry one in-flight
// request at a time. UDSClient owns a small pool of these so unrelated
// RPCs (rule install + stats poll) don't queue behind each other.
type udsConn struct {
	mu     sync.Mutex
	conn   net.Conn
	reader *bufio.Reader
}

// UDSClient speaks the Rust loader's Unix-socket RPC.
type UDSClient struct {
	socket  string
	timeout time.Duration

	conns []*udsConn
	rr    uint64
	rrMu  sync.Mutex
}

const defaultUDSPoolSize = 4

// NewUDSClient returns a UDSClient with a small connection pool. Each
// pool slot lazily dials on first use; the wire protocol is line-
// oriented and not multiplexed, so the pool size bounds in-flight RPC
// concurrency. Defaults to 4 — enough to keep the rule-install path
// from blocking on a long-running stats poll without exhausting the
// loader's accept queue.
func NewUDSClient(socket string, timeout time.Duration) *UDSClient {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	c := &UDSClient{socket: socket, timeout: timeout}
	c.conns = make([]*udsConn, defaultUDSPoolSize)
	for i := range c.conns {
		c.conns[i] = &udsConn{}
	}
	return c
}

// pick returns the next pool slot via round-robin. The slot's mutex
// is held by the caller for the duration of the RPC.
func (c *UDSClient) pick() *udsConn {
	c.rrMu.Lock()
	idx := c.rr % uint64(len(c.conns))
	c.rr++
	c.rrMu.Unlock()
	return c.conns[idx]
}

func (c *UDSClient) ensureConn(slot *udsConn) error {
	if slot.conn != nil {
		return nil
	}
	d := net.Dialer{Timeout: c.timeout}
	conn, err := d.Dial("unix", c.socket)
	if err != nil {
		return fmt.Errorf("dial dataplane socket %s: %w", c.socket, err)
	}
	slot.conn = conn
	slot.reader = bufio.NewReader(conn)
	return nil
}

func (c *UDSClient) resetSlot(slot *udsConn) {
	if slot.conn != nil {
		_ = slot.conn.Close()
		slot.conn = nil
		slot.reader = nil
	}
}

func (c *UDSClient) call(ctx context.Context, req map[string]any, out any) error {
	slot := c.pick()
	slot.mu.Lock()
	defer slot.mu.Unlock()

	if err := c.ensureConn(slot); err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(c.timeout)
	}
	_ = slot.conn.SetDeadline(deadline)

	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if _, err := slot.conn.Write(body); err != nil {
		c.resetSlot(slot)
		return fmt.Errorf("write rpc: %w", err)
	}
	line, err := slot.reader.ReadBytes('\n')
	if err != nil {
		c.resetSlot(slot)
		return fmt.Errorf("read rpc: %w", err)
	}
	var env struct {
		OK     bool            `json:"ok"`
		Error  string          `json:"error,omitempty"`
		Result json.RawMessage `json:"result,omitempty"`
	}
	if err := json.Unmarshal(line, &env); err != nil {
		return fmt.Errorf("decode rpc: %w", err)
	}
	if !env.OK {
		if env.Error == "" {
			env.Error = "unspecified rpc error"
		}
		return errors.New(env.Error)
	}
	if out != nil && len(env.Result) > 0 {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

// AddBlocklist sends an add_blocklist op.
func (c *UDSClient) AddBlocklist(ctx context.Context, prefix netip.Prefix) error {
	op := "add_blocklist_v4"
	if prefix.Addr().Is6() {
		op = "add_blocklist_v6"
	}
	return c.call(ctx, map[string]any{"op": op, "prefix": prefix.String()}, nil)
}

// RemoveBlocklist sends a remove_blocklist op.
func (c *UDSClient) RemoveBlocklist(ctx context.Context, prefix netip.Prefix) error {
	op := "remove_blocklist_v4"
	if prefix.Addr().Is6() {
		op = "remove_blocklist_v6"
	}
	return c.call(ctx, map[string]any{"op": op, "prefix": prefix.String()}, nil)
}

// SetRatelimit sends a set_ratelimit op.
func (c *UDSClient) SetRatelimit(ctx context.Context, src netip.Addr, pps uint64) error {
	return c.call(ctx, map[string]any{"op": "set_ratelimit", "src": src.String(), "pps": pps}, nil)
}

// ClearRatelimit sends a clear_ratelimit op.
func (c *UDSClient) ClearRatelimit(ctx context.Context, src netip.Addr) error {
	return c.call(ctx, map[string]any{"op": "clear_ratelimit", "src": src.String()}, nil)
}

// EnableSynCookie sends an enable_syncookie op.
func (c *UDSClient) EnableSynCookie(ctx context.Context, port uint16) error {
	return c.call(ctx, map[string]any{"op": "enable_syncookie", "port": port}, nil)
}

// DisableSynCookie sends a disable_syncookie op.
func (c *UDSClient) DisableSynCookie(ctx context.Context, port uint16) error {
	return c.call(ctx, map[string]any{"op": "disable_syncookie", "port": port}, nil)
}

// Snapshot returns the loader's view of installed rules.
func (c *UDSClient) Snapshot(ctx context.Context) (Snapshot, error) {
	var raw struct {
		BlocklistV4    []string          `json:"blocklist_v4"`
		BlocklistV6    []string          `json:"blocklist_v6"`
		Ratelimits     map[string]uint64 `json:"ratelimits"`
		SynCookiePorts []uint16          `json:"syncookie_ports"`
	}
	if err := c.call(ctx, map[string]any{"op": "snapshot"}, &raw); err != nil {
		return Snapshot{}, err
	}
	out := Snapshot{Ratelimits: make(map[netip.Addr]uint64, len(raw.Ratelimits))}
	for _, s := range raw.BlocklistV4 {
		if p, err := netip.ParsePrefix(s); err == nil {
			out.BlocklistV4 = append(out.BlocklistV4, p)
		}
	}
	for _, s := range raw.BlocklistV6 {
		if p, err := netip.ParsePrefix(s); err == nil {
			out.BlocklistV6 = append(out.BlocklistV6, p)
		}
	}
	for k, v := range raw.Ratelimits {
		if a, err := netip.ParseAddr(k); err == nil {
			out.Ratelimits[a] = v
		}
	}
	out.SynCookiePorts = raw.SynCookiePorts
	return out, nil
}

// Stats reads PERCPU counters from the loader.
func (c *UDSClient) Stats(ctx context.Context) (Stats, error) {
	var s Stats
	if err := c.call(ctx, map[string]any{"op": "stats"}, &s); err != nil {
		return Stats{}, err
	}
	return s, nil
}

// Close drops every pooled connection.
func (c *UDSClient) Close() error {
	for _, slot := range c.conns {
		slot.mu.Lock()
		c.resetSlot(slot)
		slot.mu.Unlock()
	}
	return nil
}
