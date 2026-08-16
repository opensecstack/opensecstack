// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package exfil

import (
	"context"
	"net"
	"testing"
)

func TestSplitIntoChunks_EvenDivision(t *testing.T) {
	chunks := splitIntoChunks("ABCDEFGHIJ", 5)
	if len(chunks) != 2 || chunks[0] != "ABCDE" || chunks[1] != "FGHIJ" {
		t.Errorf("chunks = %v, want [ABCDE FGHIJ]", chunks)
	}
}

func TestSplitIntoChunks_RemainderKept(t *testing.T) {
	chunks := splitIntoChunks("ABCDEFG", 3)
	if len(chunks) != 3 || chunks[2] != "G" {
		t.Errorf("chunks = %v, want 3 chunks ending in G", chunks)
	}
}

func TestSplitIntoChunks_EmptyString(t *testing.T) {
	chunks := splitIntoChunks("", 5)
	if len(chunks) != 0 {
		t.Errorf("expected no chunks for empty input, got %v", chunks)
	}
}

func TestBuildDNSQuery_HeaderAndQuestionStructure(t *testing.T) {
	q := buildDNSQuery("test.example.com", 0x1234)
	if len(q) < 12 {
		t.Fatalf("query too short: %d bytes", len(q))
	}
	// Transaction ID.
	if q[0] != 0x12 || q[1] != 0x34 {
		t.Errorf("tx ID = %02x%02x, want 1234", q[0], q[1])
	}
	// QDCOUNT = 1.
	if q[4] != 0x00 || q[5] != 0x01 {
		t.Errorf("QDCOUNT = %02x%02x, want 0001", q[4], q[5])
	}
	// First question label length should be 4 ("test").
	if q[12] != 4 {
		t.Errorf("first label length = %d, want 4", q[12])
	}
	if string(q[13:17]) != "test" {
		t.Errorf("first label = %q, want test", string(q[13:17]))
	}
}

func TestCheckDNSServer_AllowsLoopbackAndPrivate(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "10.0.0.5", "192.168.1.1"} {
		if err := checkDNSServer(context.Background(), host); err != nil {
			t.Errorf("checkDNSServer(%q) = %v, want nil", host, err)
		}
	}
}

func TestCheckDNSServer_BlocksPublicIP(t *testing.T) {
	if err := checkDNSServer(context.Background(), "8.8.8.8"); err == nil {
		t.Error("expected public DNS IP to be blocked")
	}
}

func TestDNSTunnelAttack_Run_MissingDNSServer(t *testing.T) {
	d := NewDNSTunnelAttack()
	_, err := d.Run(context.Background(), map[string]any{})
	if err == nil {
		t.Fatal("expected error when dns_server param is missing")
	}
}

func TestDNSTunnelAttack_Run_BlocksPublicDNSServer(t *testing.T) {
	d := NewDNSTunnelAttack()
	_, err := d.Run(context.Background(), map[string]any{"dns_server": "8.8.8.8:53"})
	if err == nil {
		t.Fatal("expected error for public DNS server")
	}
}

func TestDNSTunnelAttack_Run_ChannelOpenWhenServerResponds(t *testing.T) {
	conn, err := new(net.ListenConfig).ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer conn.Close()

	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			// Echo back a minimal "response" so the tunnel sees a reply.
			_, _ = conn.WriteTo(buf[:n], addr)
		}
	}()

	addr := conn.LocalAddr().String()

	d := NewDNSTunnelAttack()
	result, err := d.Run(context.Background(), map[string]any{
		"dns_server": addr,
		"payload":    "test-payload",
		"chunk_size": 10,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatal("expected Success=true when the DNS server echoes a response")
	}
	if result.QueriesResolved == 0 {
		t.Error("expected QueriesResolved > 0")
	}
	if result.QueriesSent == 0 {
		t.Error("expected QueriesSent > 0")
	}
}

func TestDNSTunnelAttack_Run_BlockedWhenNoResponse(t *testing.T) {
	// Bind and immediately close so nothing answers.
	conn, err := new(net.ListenConfig).ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	addr := conn.LocalAddr().String()
	conn.Close()

	d := NewDNSTunnelAttack()
	result, err := d.Run(context.Background(), map[string]any{
		"dns_server": addr,
		"payload":    "x",
		"chunk_size": 10,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Error("expected Success=false when no DNS server responds")
	}
	if result.QueriesBlocked == 0 {
		t.Error("expected QueriesBlocked > 0")
	}
}
