// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package recon

import (
	"context"
	"net"
	"strconv"
	"testing"
)

func TestPortScanner_Run_BlocksPublicTarget(t *testing.T) {
	p := NewPortScanner()
	_, err := p.Run(context.Background(), "8.8.8.8", nil)
	if err == nil {
		t.Fatal("expected error for public target host")
	}
}

func TestPortScanner_Run_FindsOpenPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	p := NewPortScanner()
	result, err := p.Run(context.Background(), "127.0.0.1", map[string]any{
		"start_port":  port,
		"end_port":    port,
		"timeout_ms":  500,
		"concurrency": 1,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatal("expected Success=true for an open port")
	}
	if len(result.OpenPorts) != 1 || result.OpenPorts[0].Port != port {
		t.Errorf("OpenPorts = %v, want [{Port: %d}]", result.OpenPorts, port)
	}
}

func TestPortScanner_Run_NoOpenPortsInRange(t *testing.T) {
	// Reserve a port and close the listener so nothing is bound.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	ln.Close()

	p := NewPortScanner()
	result, err := p.Run(context.Background(), "127.0.0.1", map[string]any{
		"start_port":  port,
		"end_port":    port,
		"timeout_ms":  200,
		"concurrency": 1,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Error("expected Success=false when no ports are open")
	}
	if len(result.OpenPorts) != 0 {
		t.Errorf("expected no open ports, got %v", result.OpenPorts)
	}
}

func TestPortScanner_Run_SwapsInvertedRange(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	p := NewPortScanner()
	// start_port > end_port — should be swapped internally.
	result, err := p.Run(context.Background(), "127.0.0.1", map[string]any{
		"start_port":  port,
		"end_port":    port - 1,
		"timeout_ms":  500,
		"concurrency": 1,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected the inverted range to be corrected and find the open port")
	}
}

func TestIntParam_ReconPackage(t *testing.T) {
	if got := intParam(map[string]any{}, "k", 10, 100); got != 10 {
		t.Errorf("default: got %d, want 10", got)
	}
	if got := intParam(map[string]any{"k": 500}, "k", 10, 100); got != 100 {
		t.Errorf("capped: got %d, want 100", got)
	}
	if got := intParam(map[string]any{"k": -1}, "k", 10, 100); got != 10 {
		t.Errorf("non-positive falls back to default: got %d, want 10", got)
	}
}

func TestSanitiseBanner(t *testing.T) {
	got := sanitiseBanner([]byte("SSH-2.0-OpenSSH\x00\x01\x02_extra"))
	if got == "" {
		t.Error("expected non-empty sanitised banner")
	}
	for _, r := range got {
		if r < 0x20 || r >= 0x7f {
			t.Errorf("banner contains non-printable char: %q", got)
			break
		}
	}
}

func TestSanitiseBanner_TruncatesLongInput(t *testing.T) {
	long := make([]byte, 200)
	for i := range long {
		long[i] = 'A'
	}
	got := sanitiseBanner(long)
	if len(got) != 80 {
		t.Errorf("len(got) = %d, want 80 (truncated)", len(got))
	}
}
