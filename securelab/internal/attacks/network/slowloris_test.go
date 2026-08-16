// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package network

import (
	"bufio"
	"context"
	"net"
	"testing"
)

func TestSlowloris_Run_BlocksPublicTarget(t *testing.T) {
	s := NewSlowloris()
	_, err := s.Run(context.Background(), "1.1.1.1", "80", nil)
	if err == nil {
		t.Fatal("expected error for public IP target")
	}
}

func TestSlowloris_Run_OpensConnectionsToLoopback(t *testing.T) {
	ln, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "127.0.0.1:0")
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
			// Read whatever partial data comes in, keep the connection open.
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				buf := make([]byte, 256)
				for {
					if _, err := r.Read(buf); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())

	s := NewSlowloris()
	result, err := s.Run(context.Background(), "127.0.0.1", port, map[string]any{
		"connections":   5,
		"duration":      "200ms",
		"send_interval": "50ms",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected Success=true after opening connections to a live listener")
	}
	if result.Technique != "Slowloris" {
		t.Errorf("Technique = %q, want Slowloris", result.Technique)
	}
}

func TestSlowloris_Run_NoListenerNoSuccess(t *testing.T) {
	// Bind then close to obtain a loopback port nothing is listening on.
	ln, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()

	s := NewSlowloris()
	result, err := s.Run(context.Background(), "127.0.0.1", port, map[string]any{
		"connections":   3,
		"duration":      "100ms",
		"send_interval": "50ms",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Error("expected Success=false when no connections could be opened")
	}
}
