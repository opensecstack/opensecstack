# OpenScrub Security Policy

> **Canonical threat model:** [docs/security/threat-model.md](docs/security/threat-model.md)
> — STRIDE for the kernel attack surface, IOC poisoning, rule injection,
> loader privilege escalation. Read this before contributing to the
> data plane.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities** —
this exposes deployers before a fix is available. **Kernel-attack-
surface findings are treated as critical-severity by default** and
routed directly to the core security team.

| Channel | Address | Use for |
|---|---|---|
| GitHub Security Advisory | `github.com/opensecstack/opensecstack/security/advisories/new` | Preferred. Private. GitHub handles coordination. |
| Email | `security@opensecstack.org` | Alternative if GitHub advisory not accessible. |
| PGP encrypted email | Fingerprint published at `https://opensecstack.org/.well-known/security.txt` | Kernel disclosures and any vulnerability requiring encryption. |

See the root [SECURITY.md](../SECURITY.md) for ecosystem-wide
disclosure policy and response SLA.

## Scope

**IN SCOPE:**

- Go API server (`cmd/openscrub`, `internal/`)
- Rust + Aya dataplane (`rust/dataplane/`)
- eBPF/C data-plane program (`ebpf/`)
- React frontend (`web/`)
- Loader privilege model (`CAP_BPF`, `CAP_NET_ADMIN`)
- BPF map ABI (blocklist LPM, rate-limit map)
- ThreatFlow IOC puller — IOC validation + map-reconcile path
- CITADEL `openscrub.mitigation` evidence emitter
- Docker images published to `ghcr.io/opensecstack/openscrub:*`
- Helm chart at `deploy/helm/openscrub/`

**OUT OF SCOPE:**

- Linux kernel itself (report upstream; notify us so we can pin / patch)
- libbpf / Aya upstream (report upstream; notify us)
- ThreatFlow IOC accuracy (raise as a ThreatFlow content issue)
- Generic L7 / WAF feature requests (OpenScrub is L3/L4 only)
- DDoS volumetric attacks past NIC line rate (out of architectural scope)

## Severity classification

OpenScrub uses four tiers. **Kernel attack surface is the top tier.**

| Tier | Examples | Triage SLA | Fix SLA |
|---|---|---|---|
| **Critical (kernel)** | XDP map injection from userspace, loader RCE, BPF verifier bypass leading to host kernel write | 24 h | 7 days |
| **High** | API auth bypass, IOC source compromise, rule poisoning via API, sensitive data leak | 72 h | 30 days |
| **Medium** | DoS of the API control plane (data plane unaffected), audit-log gaps, dashboard XSS | 7 days | 90 days |
| **Low** | Hardening recommendations, defence-in-depth requests | 30 days | next release |

## Threat model summary

Full STRIDE model: [docs/security/threat-model.md](docs/security/threat-model.md).

The four axes that get the most scrutiny:

1. **XDP map injection** — adversary writes a crafted entry into the
   BPF blocklist map (LPM trie) to either block legitimate traffic
   (DoS amplification) or shadow a malicious /32 with a permissive
   wider prefix.
2. **Rule poisoning via API** — adversary with API access creates a
   `0.0.0.0/0` block rule, blackholing all traffic. Mitigation: rule
   validation, rate-limit on rule creation, NDS Gate-3 separation
   between rule-author and rule-approver roles in CITADEL.
3. **IOC source compromise** — ThreatFlow is compromised and feeds
   poisoned IOCs. Mitigation: per-IOC source signature verification,
   sanity-check against allowlist of operator-owned CIDRs.
4. **Loader privilege escalation** — the loader holds `CAP_BPF` +
   `CAP_NET_ADMIN`. Any RCE in the loader is critical. Mitigation:
   loader minimal in size, no network listener (Unix socket only),
   strict input validation on the control protocol.

## Hardening defaults

- Dataplane Unix socket `/run/openscrub/dataplane.sock`: target mode is
  `0660 root:openscrub` (uid/gid 9087 — the orchestrator manifests
  ship that group). The dataplane process applies the mode at bind
  time when `OPENSCRUB_SOCKET_MODE` is set; otherwise the socket
  inherits the orchestrator's umask.
- API binds to a configurable interface (default localhost when not in compose).
- `/api/v1/metrics` is **JWT-gated** in v1.0 — counters reveal
  operational state (rule counts, IOC pull cadence, CITADEL queue
  depth) so the endpoint requires a Bearer token. Provision a
  long-lived "readonly" JWT for Prometheus and load it from a file
  (see [deploy/prometheus.yml](deploy/prometheus.yml)). Bind to a
  private interface in addition to the auth gate when network policy
  allows.
- JWT secret rotated via env var; sessions are short (1 hour default).
- All inter-platform webhooks HMAC-SHA256 signed with ±5-minute replay window.

## Disclosure terms

We follow standard coordinated disclosure with a 90-day default
embargo, extendable by mutual agreement when a kernel patch is in
flight upstream. Reporters credited in the advisory unless they
prefer anonymity.
