package dataplane

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestStatsJSONRoundTrip ensures the Stats struct decodes every field
// the Rust loader emits — in particular `syn_cookies_sent`, which the
// pre-BLOCKER-2 Stats struct silently dropped (Snapshot endpoint then
// reported 0 even when the loader had emitted SYN-cookies).
func TestStatsJSONRoundTrip(t *testing.T) {
	body := []byte(`{
	    "packets_passed":      10,
	    "packets_dropped":     20,
	    "packets_ratelimited": 30,
	    "packets_malformed":   40,
	    "syn_cookies_sent":    50
	}`)
	var s Stats
	if err := json.Unmarshal(body, &s); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if s.PacketsPassed != 10 || s.PacketsDropped != 20 ||
		s.PacketsRatelimited != 30 || s.PacketsMalformed != 40 ||
		s.SynCookiesSent != 50 {
		t.Fatalf("decoded mismatch: %+v", s)
	}
}

// TestUDSClientStatsCarriesSynCookies wires a fake UDS server that
// echoes the loader's stats payload and asserts the Go client surfaces
// the syn_cookies_sent field. Skipped on Windows where unix sockets
// behave differently in the test harness.
func TestUDSClientStatsCarriesSynCookies(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix-domain sockets not exercised on Windows in this harness")
	}
	dir := t.TempDir()
	socket := filepath.Join(dir, "dp.sock")

	ln, err := new(net.ListenConfig).Listen(context.Background(), "unix", socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		_ = n
		// Reply once. The Go client uses a line-oriented protocol.
		_, _ = conn.Write([]byte(`{"ok":true,"result":{"packets_passed":1,"packets_dropped":2,"packets_ratelimited":3,"packets_malformed":4,"syn_cookies_sent":99}}` + "\n"))
	}()

	c := NewUDSClient(socket, time.Second)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s, err := c.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if s.SynCookiesSent != 99 {
		t.Fatalf("expected SynCookiesSent=99, got %d (full stats=%+v)", s.SynCookiesSent, s)
	}
}
