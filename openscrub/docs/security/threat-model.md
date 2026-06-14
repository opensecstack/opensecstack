# OpenScrub Threat Model

> v1.0.0. STRIDE applied to the kernel attack surface. Companion to
> [SECURITY.md](../../SECURITY.md). **Kernel-attack-surface findings
> are the highest disclosure tier in this module.**

## Trust boundaries

```
   ┌──────────────────────────────────────────────────────────────┐
   │ Internet ingress (untrusted, adversarial)                    │
   │  ── packets ──────────────────────────────────────────────►  │
   └──────────────────────────────┬───────────────────────────────┘
                                  │
                       ─── boundary T1 ───
                                  │
   ┌──────────────────────────────┴────────────────────────────────┐
   │ Kernel — XDP program, BPF maps, NIC driver                    │
   │ Adversary capability inside T1: crafted packet contents only  │
   └──────────────────────────────┬────────────────────────────────┘
                                  │
                       ─── boundary T2 ───
                                  │
   ┌──────────────────────────────┴────────────────────────────────┐
   │ Loader (Rust) — userspace, CAP_BPF + CAP_NET_ADMIN            │
   │ Communicates only via /run/openscrub/dataplane.sock           │
   └──────────────────────────────┬────────────────────────────────┘
                                  │
                       ─── boundary T3 ───
                                  │
   ┌──────────────────────────────┴────────────────────────────────┐
   │ API (Go) — userspace, no caps. JWT-authenticated REST.        │
   └──────────────────────────────┬────────────────────────────────┘
                                  │
                       ─── boundary T4 ───
                                  │
   ┌──────────────────────────────┴────────────────────────────────┐
   │ Operators (browser dashboard) + integrators (ThreatFlow)      │
   └───────────────────────────────────────────────────────────────┘
```

## STRIDE table

| # | Threat | Category | Surface | Likelihood | Impact | Mitigation |
|:-:|---|---|---|---|---|---|
| 1 | **XDP map injection** — malicious userspace process pins a fake map and tricks the loader into reading it | Tampering | T2 | Low | Critical | BPF pin dir is `0700 root:openscrub`; loader verifies map ABI on boot; all entries written via authenticated control socket |
| 2 | **Rule poisoning via API** — operator with `rule:write` creates `0.0.0.0/0` block, blackholes traffic | Tampering, DoS | T3 | Medium | High | Default deny on prefix shorter than `/8`; `X-Confirm-Dangerous` header + `rule:dangerous` scope; CITADEL Gate-3 NDS for cross-author/approver separation |
| 3 | **IOC source compromise** — ThreatFlow upstream is compromised, ships poisoned malicious-IP feed | Tampering | T4 | Medium | High | Per-source signature on the feed bundle; allow-list of operator-owned CIDRs that IOC pull cannot block; max delta per pull cycle |
| 4 | **Loader RCE** — bug in the control-socket parser leads to memory corruption inside the loader | Elevation of Privilege | T2 | Low | Critical | Rust + serde, no `unsafe` in the parse path; loader unit-tested with fuzzed control messages; AppArmor/SELinux profile constrains loader fs/net |
| 5 | **BPF verifier bypass leading to kernel write** | Elevation of Privilege | T1, T2 | Very low | Critical | Pin to BTF-typed access only; `unprivileged_bpf_disabled=1`; track upstream kernel CVEs; refuse to load on kernel < 5.15 |
| 6 | **Information disclosure via timing** — adversary infers CIDR membership from drop timing | Information Disclosure | T1 | Low | Low | LPM lookup is constant-ish-time; XDP_DROP returns no signal to source by default |
| 7 | **DoS of the API** — control plane DoS while data plane runs fine | DoS | T3 | Medium | Low | Rate-limit on `/auth/login` and `/rules`; the data plane is unaffected by API outage; existing maps continue to drop |
| 8 | **Audit-log gaps** — adversary deletes rule and tampers with `audit_log` | Repudiation | T3, T4 | Low | High | Audit rows are mirrored as `openscrub.mitigation` / `openscrub.rule_change` events to CITADEL WORM, signed and chained — Postgres tampering does not erase the WORM record |
| 9 | **Spoofed CITADEL endpoint** — adversary stands up a fake CITADEL receiver | Spoofing | T4 | Low | Medium | HMAC-SHA256 with shared secret; mTLS optional; `OPENSCRUB_CITADEL_API_URL` is operator-configured |
| 10 | **JWT secret leak** — operator pastes `OPENSCRUB_JWT_SECRET` somewhere public | Spoofing | T3 | Medium | Medium | Short TTL (1 h default); rotation invalidates all sessions; secret never logged |

## High-tier kernel surface — summary

The four threats that carry the SECURITY.md "Critical (kernel)" tier:

- #1 XDP map injection
- #4 Loader RCE
- #5 BPF verifier bypass
- (Implicit) any kernel CVE in the XDP / verifier path while
  OpenScrub is the loaded program

These get a 24 h triage SLA and 7-day fix SLA per
[SECURITY.md](../../SECURITY.md).

## Out of model

- L7 DDoS (HTTP flood, slowloris). Outside data plane scope.
- Volumetric attacks past NIC line rate. Solved upstream (BGP
  scrubbing partner), not in OpenScrub.
- Side-channel attacks against the loader process from a co-tenant
  on the same host. Operators should treat OpenScrub-running nodes
  as security-tier-1 and not co-locate untrusted workloads.

## Compliance traceability

| Control | NIS2 Article 21(2) measure | Evidence in OpenScrub |
|---|---|---|
| Mitigation action audit | (c) Incident handling | `audit_log` table + CITADEL `openscrub.mitigation` events |
| Access control | (i) Access control | JWT + RBAC scopes, NDS Gate-3 cross-role separation |
| Threat intelligence integration | (g) Cybersecurity training, (h) Vulnerability handling | ThreatFlow IOC pull |
| Cryptography | (h) | HMAC-SHA256 on CITADEL emissions, JWT HS256 (configurable to RS256) |
