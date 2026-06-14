# Deployment Topology

This document describes how the OpenSecStack platforms wire together
in practice — which ports they listen on, which talk to which, and
what network segments you typically place them on. It is the companion
to [security-maturity.md](./security-maturity.md); the tier guidance
there assumes the topology described here.

For per-platform deployment specifics, see each platform's own
`docs/deployment.md` (where available).

## Port matrix

| Platform | API port | Dashboard | Notes |
|---|---|---|---|
| APIGuard | 8080 | 3000 | Public-facing scanning engine |
| NIS2 Compass | 8090 | 3001 | Python + Flask |
| CITADEL | 8099 | — (no UI) | Internal-only; governance engine |
| IRFlow | 8083 | — (dashboard planned) | Incident response orchestrator |
| ThreatFlow | 8084 | — (dashboard planned) | IOC aggregation |
| **OpenScrub** | **8087** | **3087** | **v1.0.0 — XDP/eBPF DDoS mitigation; loader runs hostNetwork on edge nodes** |
| (scaffolded) CyberPath | 8086 | 3006 | Security training; Phase 2 kickoff |
| (planned) SecureLab | 8085 | 3007 | Attack simulation sandbox |
| **OpenCSIRT** | **8088** | **3088** | **v1.0.0 — Go API; Python advisory subsystem on `:8089` (loopback / NetworkPolicy locked to API Pods)** |
| **VertGuard** | **8091** | **3009** | **v1.0.0 — AI-attack defence: prompt injection, C2PA media, AI threat feed, deepfake video/voice; Python ML gRPC on `:50051`** |
| PostgreSQL (per platform) | 5432 | — | Internal — one DB instance per platform for isolation |
| gRPC (VertGuard ML service) | 50051 | — | Internal-only; Python ML inference side-car for VertGuard — active (HuggingFace sklearn backend; stub backend when model weights absent) |

Every platform exposes `/metrics` on its main API port for Prometheus
scrapes; that path is deliberately unauthenticated so scrapers don't
need to manage JWTs.

## Single-host topology (Tier 1 — standard deployment)

```
                               +----------------------------+
       internet  ─────────────►|  Ingress / Load balancer   |
                               |  (Traefik, nginx, Caddy)   |
                               |  terminates TLS            |
                               +-------------+--------------+
                                             |
                               +-------------v--------------+
                               |      Docker network        |
                               |      "opensecstack"        |
                               +-------------+--------------+
                                             |
           +---------+-----------+-----------+-----------+-----------+
           |         |           |           |           |           |
        apiguard  nis2compass citadel     irflow    threatflow   postgres
         :8080     :8090      :8099      :8083      :8084       :5432
```

All services live on one docker-compose network, TLS terminates at the
ingress, and inter-service traffic is plain HTTP inside the trusted
Docker network. This is the default layout shipped with the
`deploy/docker-compose.yml` stack.

Suitable for:

- NGOs, regional public administration, mid-sized enterprises
- Research labs and internal corporate deployments
- Any deployment on Tier 1 of the [security maturity matrix](./security-maturity.md#tier-1--standard-deployment)

## Multi-host topology (Tier 2 — elevated deployment)

```
                               +----------------------------+
      internet  ──────────────►|  WAF + API gateway         |
                               |  (Cloudflare, Kong, Envoy) |
                               +-------------+--------------+
                                             |
                          +------------------+------------------+
                          |      service mesh (mTLS everywhere) |
                          |         Istio / Linkerd             |
                          +------------------+------------------+
                                             |
   +----------------------+----------------------+----------------------+
   |                      |                      |                      |
+--v------+  +----+-------v---+  +--+---------+--v------+  +-----+---+-v+
|apiguard |  |nis2|compass    |  |citadel     |irflow   |  |threat|flow|
|(replicas|  |(rep|licas)     |  |(primary +  |(replicas)| |(repli|cas)|
+--+------+  +----+-----------+  +--+---------+---------+  +-----+-----+
   |              |                  |  standby for HA)       |
   +------+-------+---+--------------+------+-----------------+
          |           |                     |
          |           |                     |
      +---v---+   +---v---+             +---v---+
      |postgres|  |postgres|            |vault  |  (secret manager)
      |APIGuard|  |NIS2    |            |       |  (HashiCorp Vault,
      +-------+   +-------+             +-------+   AWS Secrets Manager,
                                                    or GCP Secret Mgr)
```

Key additions over Tier 1:

- **Service mesh** (Istio, Linkerd) enforces mTLS between every pair of
  platforms; inter-platform plain-HTTP traffic disappears.
- **Secret manager** (Vault, AWS/GCP Secret Manager) replaces
  environment variables as the source of long-lived secrets. Platforms
  are either configured with secret-manager CSI drivers in Kubernetes
  or with sidecars that inject secrets into memory at process start.
- **Separate databases** per platform on the same managed PostgreSQL
  fleet, with least-privilege users and per-database encryption keys.
- **CITADEL HA** = active primary + standby with external leader lock
  (Consul, Kubernetes Lease). WORM chain stays single-writer; standby
  takes over only on confirmed primary failure to avoid divergence.
- **Upstream WAF** (Cloudflare, AWS WAF, Google Cloud Armor) handles
  rate-limiting, DDoS absorption, and edge-level filtering — IRFlow,
  APIGuard, etc. don't try to do that themselves.

This is the recommended profile for:

- Multi-region SaaS deployments
- Large enterprises spanning multiple business units
- Organisations with zero-trust mandates
- Anything on Tier 2 of the [security maturity matrix](./security-maturity.md#tier-2--elevated-deployment)

## Traffic map (who calls whom)

```
                             +---------+                 +----------------+
                             | APIGuard|◄────────────────|  Internet      |
                             |         |  scan requests  |  users / CI    |
                             +----+----+                 +----------------+
                                  │
             findings / scan done │
                  webhook (HMAC)  ▼
                             +---------+
                             | IRFlow  |◄─┐                 +------------+
                             |         |  │                 | ThreatFlow |
                             +----+----+  │                 |            |
                                  │       │                 +-----+------+
                 MARSHAL evaluate │       │  ioc_bundle           │
                  WORM emit       ▼       │  webhook (HMAC)       │
                             +---------+  └───────────────────────┘
                             | CITADEL |
                             |         |◄──────────┐
                             +----+----+           │
                                  │                │
                     WORM emit    │     HARD_STOP  │ webhook
                         (HMAC)   ▼     (HMAC)     │
                             +---------+           │
                             |NIS2     |           │
                             |Compass  |           │
                             +---------+           │
                                                   │
                                  (also receives)  │
                                                   │
                          Internet admin users ────┘
                          authenticate with JWT
```

In short:

- **Every API client** authenticates with an HS256 JWT bearer token.
- **Every platform-to-platform webhook** (APIGuard → IRFlow, CITADEL →
  IRFlow, ThreatFlow → IRFlow, ThreatFlow → OpenCSIRT, VertGuard → IRFlow/ThreatFlow/OpenCSIRT) is
  HMAC-SHA256 signed with a per-source secret and a ±5-minute replay
  window.
- **Every platform-to-CITADEL call** is HMAC-SHA256 signed with the
  shared CITADEL secret.
- **CITADEL fans out** to WORM writes and HARD_STOP webhook
  notifications back to IRFlow when emergency brakes are pulled.

## Network segmentation

| Zone | Contains | Access |
|---|---|---|
| **Public** | Ingress / WAF, dashboards (APIGuard UI, NIS2 Compass UI) | Internet-facing |
| **Application** | Platform API servers (ports 8080–8090) | Only ingress + internal services |
| **Governance** | CITADEL | Only IRFlow, APIGuard, NIS2 Compass, ThreatFlow can reach it |
| **Data** | PostgreSQL instances | Only the owning platform can reach its DB |
| **Observability** | Prometheus, Grafana, Jaeger | Internal ops network only |

Compromising the public zone gets you to the dashboards and the
ingress; compromising the application zone gets you the platform APIs
but not CITADEL; compromising CITADEL is the only path to history
rewrite, and even then the anchor signatures detect tampering after
the fact.

## Secret distribution

| Secret | Consumer | Where it lives |
|---|---|---|
| `IRFLOW_AUTH_SECRET` | IRFlow | Secret manager → env var |
| `IRFLOW_AUTH_PEPPER` | IRFlow (API-key hashing) | Secret manager → env var |
| `IRFLOW_CITADEL_KEY_SECRET` | IRFlow ↔ CITADEL | Shared — both sides must match |
| `IRFLOW_WEBHOOK_APIGUARD_SECRET` | IRFlow (verifier) + APIGuard (signer) | Shared |
| `IRFLOW_WEBHOOK_CITADEL_SECRET` | IRFlow (verifier) + CITADEL (signer) | Shared |
| `IRFLOW_WEBHOOK_THREATFLOW_SECRET` | IRFlow (verifier) + ThreatFlow (signer) | Shared |
| `IRFLOW_NIS2_API_KEY` | IRFlow (caller) | IRFlow side only — NIS2 stores a hash |
| `CITADEL_ANCHOR_KEY` | CITADEL | Secret manager (never leaves the service) |

For production, one Vault / KMS path per secret, rotated on your
chosen schedule (quarterly for HMAC secrets, yearly for CITADEL anchor
key, per-DB policy for PostgreSQL passwords). See the
[CITADEL SECURITY.md § Key management](../citadel/SECURITY.md#key-management)
for the rotation runbook.

## Failure modes and mitigation

| Failure | Impact | Mitigation |
|---|---|---|
| CITADEL unreachable | All MARSHAL-gated actions across the ecosystem are blocked | Active/passive failover (Consul lease); IRFlow surfaces 503 to callers — never silently proceeds |
| PostgreSQL primary down | Owning platform is read-only (or fully down) | Managed DB with automatic failover; streaming replicas for read queries |
| IRFlow replica crashes | Short unavailability on that replica only | Load balancer removes it; Deployment spec keeps 2+ replicas healthy |
| Webhook secret rotation mid-flight | Valid signatures from the old secret briefly rejected | Overlapping-secret support is v1.1 — today, rotate during a maintenance window |
| NIS2 Compass unreachable | NIS2 Article 23 notification skipped (async retry is v1.1) | Alert on `irflow_governance_calls_total{target="nis2",result="failure"}` > 0 |

## Related

- [Ecosystem security maturity tiers](./security-maturity.md)
- [Ecosystem-wide architecture and layers](./security-architecture.md)
- [CITADEL architecture](../citadel/docs/architecture.md)
- [IRFlow deployment](../irflow/docs/deployment.md)
- [ECOSYSTEM.md](../ECOSYSTEM.md) — flow map at feature level
