# BGP Blackhole Setup

> **⚠️ PLANNED / NOT YET IMPLEMENTED.** This document describes a
> tier-2 upstream BGP blackhole mitigation capability that is
> **not present in the shipped v1.0.0 codebase**. There is no
> `internal/mitigation/bgp/` package, no embedded GoBGP server, and no
> `mitigation.bgp.*` configuration support in OpenScrub today. The
> only mitigation OpenScrub actually performs is **tier-1 XDP/eBPF
> in-kernel filtering** (blocklist / rate-limit / SYN-cookie rules) —
> see [xdp-program-guide.md](xdp-program-guide.md) and
> [architecture.md](architecture.md). This design is recorded in
> [ADR-002](../adrs/002-gobgp-integration.md) (status: Proposed) as
> intended future work and kept here for its design value, but nothing
> below is deployable against the current release. Do not configure
> `mitigation.bgp.*` expecting it to work.

## Concept: Remotely Triggered Black Hole (RTBH)

RTBH is a BGP-based DDoS mitigation technique. When a prefix is under attack, the scrubbing node announces that prefix to upstream transit providers with a community string that signals the upstream router to discard traffic destined for that prefix at the provider edge. This shifts the drop point upstream, protecting scrubbing infrastructure bandwidth.

OpenScrub implements RTBH using GoBGP as the local BGP speaker.

---

## GoBGP Integration

`internal/mitigation/bgp/gobgp.go` manages the GoBGP server lifecycle and all route operations.

Key functions:

| Function | Description |
|----------|-------------|
| `StartServer(cfg BGPConfig)` | Initialises GoBGP with the local AS and router ID from config |
| `AddPeer(peer PeerConfig)` | Establishes a BGP session to an upstream peer |
| `AnnounceBlackhole(prefix)` | Adds a host route (/32 or /128) with blackhole community |
| `WithdrawBlackhole(prefix)` | Removes the route, restoring normal forwarding |
| `PeerStatus()` | Returns session state for all configured peers |

GoBGP runs embedded in the OpenScrub process. No separate `gobgpd` daemon is needed.

---

## Community Strings

`internal/mitigation/bgp/communities.go` defines the community values sent with blackhole announcements.

Standard communities (RFC 7999):

| Community | Meaning |
|-----------|---------|
| `65535:666` | RTBH — discard at receiving router |

Operator-defined communities can be added to `openscrub.yaml` under `mitigation.bgp.communities`. Multiple communities are sent simultaneously to support multi-provider environments.

Example:

```yaml
mitigation:
  bgp:
    communities:
      - "65535:666"
      - "64496:9999"   # provider-specific blackhole
```

---

## Configuring Upstream Peer Sessions

Add peer blocks under `mitigation.bgp.peers` in `openscrub.yaml`:

```yaml
mitigation:
  bgp:
    local_as: 65001
    router_id: "10.0.0.1"
    peers:
      - address: "198.51.100.1"
        remote_as: 64500
        password: "secretMD5"
        hold_time: 90
        keepalive: 30
```

Peers must be configured on the upstream side to accept the blackhole community and apply a discard route. Coordinate with your transit provider's NOC to pre-provision the peer and community acceptance policy.

For iBGP deployments (e.g., announcing to an internal route reflector), set `remote_as` equal to `local_as`.

---

## Announcement Lifecycle

The full cycle from attack detection to route withdrawal:

```
Attack detected (FastNetMon / threshold breach)
        │
        ▼
internal/mitigation/scrubber.go evaluates tier
        │
        ▼ (tier 2 or escalated)
bgp.AnnounceBlackhole(victim_prefix)
        │  GoBGP sends UPDATE to all peers
        ▼
Upstream router installs discard route
        │  Traffic dropped at provider edge
        ▼
Attack subsides (threshold clear for cool-down period)
        │
        ▼
bgp.WithdrawBlackhole(victim_prefix)
        │  GoBGP sends WITHDRAW to all peers
        ▼
Normal forwarding restored
```

The cool-down period is configurable under `mitigation.bgp.withdraw_delay_seconds` (default: 300).

---

## blackhole.go Walk-through

`internal/mitigation/bgp/blackhole.go` is the coordination layer between the scrubber and GoBGP:

1. `Blackhole(prefix, reason, sourceEvent)` — validates the prefix is within the configured protected ranges (`mitigation.bgp.protected_prefixes`), then calls `AnnounceBlackhole`.
2. All blackhole events are written to the database with timestamp, prefix, reason, and initiating event ID.
3. `AutoWithdraw()` runs as a goroutine, polling active blackholes every 60 seconds and withdrawing those past their TTL.
4. `ForceWithdraw(prefix)` is the manual override path called by the CLI and REST API.

Protected prefixes act as a guard rail — OpenScrub will not blackhole a prefix outside the defined scope, preventing accidental null-routing of unrelated address space.
