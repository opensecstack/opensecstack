# OpenScrub Architecture

> Status: v1.0.0. Companion to [README.md](../README.md). For threat
> modelling see [security/threat-model.md](security/threat-model.md).

## Component diagram

```
                         ┌─────────────────────────┐
                         │   Operator browser      │
                         │   (React dashboard)     │
                         └────────────┬────────────┘
                                      │ HTTPS  :3087 / :443
                                      ▼
                         ┌─────────────────────────┐
                         │     OpenScrub API       │   Go (chi)
                         │     :8087               │   stateless replicas
                         │     /metrics :9091      │
                         └────┬────────┬───────┬───┘
                              │        │       │
                ┌─────────────┘        │       └────────────────┐
                │                      │                        │
                ▼                      ▼                        ▼
       ┌────────────────┐   ┌──────────────────┐   ┌────────────────────┐
       │ PostgreSQL 16  │   │ ThreatFlow API   │   │ CITADEL API        │
       │ rules · audit  │   │ IOC pull         │   │ openscrub.miti...  │
       │ mitigations    │   │ (15 min cadence) │   │ HMAC-SHA256        │
       └────────────────┘   └──────────────────┘   └────────────────────┘
                              │
                              ▼  reconcile blocklist into BPF map
                ┌──────────────────────────────────────┐
                │  /run/openscrub/dataplane.sock          │
                │  (Unix socket, control protocol)     │
                └──────────────────┬───────────────────┘
                                   │
                                   ▼
                ┌──────────────────────────────────────┐
                │      OpenScrub loader                │
                │      Rust + Aya (per-node DaemonSet) │
                │      CAP_BPF + CAP_NET_ADMIN         │
                │                                      │
                │   pinned BPF maps (/sys/fs/bpf):     │
                │     · blocklist (LPM-trie)           │
                │     · ratelimit (per-CIDR pps)       │
                │     · stats (drop / pass counters)   │
                │                                      │
                │   ┌──────────────────────────────┐   │
                │   │  eBPF/C program (XDP)        │   │
                │   │  attach: NIC RX queue        │   │
                │   │  decision: DROP | PASS       │   │
                │   └──────────────────────────────┘   │
                └──────────────────┬───────────────────┘
                                   ▲
                                   │
                              network ingress
```

## Data flow — block decision

1. Operator (or ThreatFlow puller) creates a rule via `POST /api/v1/rules`.
2. API validates (CIDR, type, pps, ttl), persists row in `rules`.
3. API sends a `RULE_INSERT` message on the loader Unix socket.
4. Loader writes the entry into the LPM-trie BPF map (or rate-limit
   map for `ratelimit` rules).
5. On packet ingress, the XDP program does an LPM lookup. Hit →
   `XDP_DROP` (or rate-limit branch). Miss → `XDP_PASS`.
6. Drop counters are written to a per-CPU `stats` map.
7. A userspace reader in the API process aggregates the stats map
   every 1 s, writes a `mitigation` row, and emits an
   `openscrub.mitigation` event to CITADEL (async, fire-and-retry).

## Why a Unix socket between API and loader

- Privilege boundary: the loader holds `CAP_BPF` + `CAP_NET_ADMIN`.
  The API does not. The API process can be replicated, restarted,
  exposed publicly. The loader can be one-per-node and never accept
  network connections.
- Filesystem permissions on `/run/openscrub/dataplane.sock` are managed
  by the dataplane process at bind time. Default mode is the umask
  inherited from the orchestrator (compose / Helm tmpfs / hostPath). To
  enforce `0660 root:openscrub` set `OPENSCRUB_SOCKET_MODE=0660` and run
  the loader inside the `openscrub` group; the orchestrator manifests
  ship that group on uid/gid 9087.

## Why XDP and not iptables / nftables

- XDP runs at NIC ingress, before `skb` allocation. A drop costs ~50
  ns on commodity hardware vs. ~µs for nftables.
- LPM-trie maps support ~1M prefixes with O(log W) lookup where W is
  the address width, so blocklist size scales with ThreatFlow output.
- No userspace copy on drop = no cache pressure during a flood.

## Why Postgres and not just BPF maps

- BPF maps are ephemeral (lost on loader restart). The Postgres row
  is the source of truth; map state is reconciled from Postgres on
  loader start.
- Audit/forensics: every rule mutation is captured in `audit_log`
  with the principal who made the change.
- CITADEL evidence emission needs a stable rule ID across restarts.

## ThreatFlow IOC pull

See [threatflow-integration.md](threatflow-integration.md). Summary:
the API process runs a goroutine on a 15-minute interval that pulls
the malicious-IP feed from ThreatFlow, diffs against the existing
`source = 'threatflow'` rules, and inserts/withdraws as needed.

## CITADEL evidence

See [citadel-integration.md](citadel-integration.md). Every distinct
mitigation event (per-rule, per-source-IP, aggregated to 1 s windows)
emits an `openscrub.mitigation` event to CITADEL, HMAC-SHA256 signed.

## Process model

| Process | Replicas | Capabilities | Network |
|---|---|---|---|
| `openscrub-api` (Go) | N (Deployment) | none | HTTP :8087, metrics :9091 |
| `openscrub-loader` (Rust) | 1 per node (DaemonSet) | CAP_BPF, CAP_NET_ADMIN | hostNetwork, no listeners |
| `openscrub-web` (nginx) | M (Deployment) | none | HTTP :80 |
| `postgres` | 1 (StatefulSet) | none | TCP 5432 (cluster-internal) |

## Failure modes

- **API down**: existing BPF maps continue to drop. New rules cannot be added.
- **Loader down**: BPF program detaches; *no filtering*. Mitigation: alert via Prometheus on loader heartbeat absence.
- **Postgres down**: API returns 503 on writes; reads may degrade. Existing maps continue to drop.
- **ThreatFlow down**: IOC feed staleness alert; existing IOC-source rules continue to drop until TTL expires.
