// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package network

import (
	"context"
	"net"
	"testing"
	"time"
)

// localTCPListener starts a TCP listener on loopback that accepts and
// immediately closes connections, returning the port.
func localTCPListener(t *testing.T) string {
	t.Helper()
	ln, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return port
}

func TestSYNFlood_Run_BlocksPublicTarget(t *testing.T) {
	s := NewSYNFlood()
	_, err := s.Run(context.Background(), "8.8.8.8", "80", nil)
	if err == nil {
		t.Fatal("expected error for public IP target")
	}
}

func TestSYNFlood_Run_SendsConnectionsToLoopback(t *testing.T) {
	port := localTCPListener(t)
	s := NewSYNFlood()

	result, err := s.Run(context.Background(), "127.0.0.1", port, map[string]any{
		"duration": "300ms",
		"pps":      50,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected Success=true after sending SYN connections to a live listener")
	}
	if result.Technique != "SYNFlood" {
		t.Errorf("Technique = %q, want SYNFlood", result.Technique)
	}
	if len(result.Evidence) == 0 {
		t.Error("expected non-empty evidence")
	}
}

func TestSYNFlood_Run_RespectsContextCancellation(t *testing.T) {
	port := localTCPListener(t)
	s := NewSYNFlood()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := s.Run(ctx, "127.0.0.1", port, map[string]any{
		"duration": "10s", // longer than the context deadline
		"pps":      50,
	})
	if err == nil {
		t.Fatal("expected context deadline exceeded error")
	}
}
