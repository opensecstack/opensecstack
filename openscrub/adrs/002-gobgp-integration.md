# ADR-002: Use GoBGP for BGP blackhole announcements

## Status
Proposed

> **Status as of 2026-07-27: not implemented.** This ADR records a
> design decision for a tier-2 (upstream BGP blackhole) mitigation
> capability. As of v1.0.0, no code implementing this decision exists
> in the codebase — there is no `internal/mitigation/bgp/` package,
> and OpenScrub does not run an embedded GoBGP instance or speak BGP
> to any peer. The only mitigation mechanism actually shipped is the
> XDP/eBPF in-kernel tier-1 data plane described in
> [ADR-001](001-xdp-over-iptables.md) and `internal/dataplane/`. This
> ADR is retained as a record of intended future work; do not treat it
> as documentation of current behaviour. It was previously marked
> "Accepted" in error — no GoBGP integration was ever built, so that
> status did not reflect reality.

## Context
Remotely Triggered Black Hole (RTBH) routing requires OpenScrub to programmatically announce /32 (IPv4) and /128 (IPv6) prefixes tagged with the blackhole community (RFC 7999: `65535:666`) to one or more upstream BGP peers. These announcements must be created, refreshed, and withdrawn automatically as the mitigation lifecycle progresses — on detection, on timeout, and on manual release.

Three BGP daemon options were evaluated:

- **Quagga / FRRouting (FRR):** Mature, widely deployed, but configuration is file-driven (`vtysh`/config reload). Programmatic route injection requires either writing config files and reloading or using the unstable Northbound API. Coupling to a file-based workflow is fragile in an automated system.
- **BIRD:** Excellent performance; route control via BIRD scripting language. No native gRPC or REST API; automation requires piping to `birdc` or parsing control-socket output. Awkward from Go.
- **GoBGP:** Written in Go; exposes a first-class gRPC API for all operations (peer management, path injection, withdrawal). Designed to be embedded or controlled programmatically.

## Decision

- GoBGP is integrated as a library dependency (not an external process) where feasible, or driven via its gRPC API from within the OpenScrub process.
- BGP logic lives under `internal/mitigation/bgp/gobgp.go`.
- Peer configuration (ASN, neighbor IP, hold timer, communities) is sourced from OpenScrub's central config; no separate BGP daemon config file is maintained.
- Route announcements are issued by calling GoBGP's gRPC `AddPath` RPC; withdrawals call `DeletePath`. The blackhole community and NEXT_HOP are set programmatically on every path object.
- The mitigation engine calls `bgp.AnnounceBlackhole(prefix)` and `bgp.WithdrawBlackhole(prefix)` as atomic operations tied to detection events.

## Consequences

**Positive:**
- No external BGP daemon process to manage, monitor, or restart separately.
- Fully automated blackhole lifecycle from Go code; no config file reloads or shell escapes.
- gRPC client is strongly typed; API misuse is caught at compile time.

**Negative:**
- Tight coupling to GoBGP's API; breaking changes in GoBGP releases require OpenScrub updates.
- gRPC adds a dependency and requires proto/gRPC toolchain for code generation.
- Operators familiar with FRR/BIRD may find GoBGP's operational model unfamiliar; `gobgp` CLI replaces `vtysh`/`birdc` for manual inspection.
- GoBGP's production adoption is narrower than FRR; long-term maintenance of the upstream project carries some risk.
