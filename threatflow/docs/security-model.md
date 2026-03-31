# ThreatFlow Security Model

## Threat Model

ThreatFlow handles sensitive intelligence data — IOCs from external feeds, internal scan results, and cross-platform correlation data. Compromise of ThreatFlow could:

1. **Poison the IOC store** — inject false positives that trigger unnecessary alerts in IRFlow
2. **Leak intelligence** — expose IOC context that reveals defensive posture
3. **Bypass governance** — skip MARSHAL gating to inject unapproved feed sources
4. **Corrupt audit trail** — tamper with WORM events to hide intelligence manipulation

---

## Security Controls

### Layer 1: Identity (L1)

| Control | Implementation |
|---------|---------------|
| API authentication | JWT for external consumers, HMAC-SHA256 for CITADEL connector |
| Feed source authentication | Per-feed API keys stored in environment variables or secrets manager |
| No anonymous writes | All mutation endpoints require authentication |
| Role-based access | Feed management requires `threatflow_admin` role |

### Layer 2: Network (L2)

| Control | Implementation |
|---------|---------------|
| TLS 1.2+ on all external connections | Enforced at ingress (cert-manager) |
| Internal communication over cluster network | K8s network policies |
| Rate limiting | nginx ingress rate limit (60 req/min) |
| No redirect following | `redirect: "error"` on all outbound HTTP |

### Layer 3: Host (L3)

| Control | Implementation |
|---------|---------------|
| Non-root container | Dockerfile: `USER threatflow` |
| Minimal base image | Alpine 3.19 — minimal attack surface |
| No shell in production | CGO_ENABLED=0 static binary |
| Read-only filesystem | K8s `readOnlyRootFilesystem: true` (recommended) |

### Layer 4: Application (L4)

| Control | Implementation |
|---------|---------------|
| CITADEL MARSHAL governance | Bulk ingestion and feed addition require EXECUTE |
| Input validation | All STIX objects validated against schema before storage |
| IOC pattern sanitisation | Patterns are normalised and hash-verified |
| Request size limits | Max body 10MB on ingestion endpoints |
| Timeout enforcement | 15s read, 60s write, 120s idle |

### Layer 5: Data (L5)

| Control | Implementation |
|---------|---------------|
| WORM logging | All mutations logged to CITADEL chain |
| Database encryption | PostgreSQL `sslmode=require` in production |
| Secret management | API keys and HMAC secrets via K8s Secrets or Vault |
| IOC expiry | Automatic TTL-based revocation — no permanent IOC retention without refresh |
| Backup | PostgreSQL WAL streaming to offsite backup |

---

## Feed Trust Model

Not all IOC feeds are equally trustworthy. ThreatFlow implements a graduated trust model:

| Trust Level | Feeds | Controls |
|-------------|-------|----------|
| **Trusted** | Internal MISP, manual analyst input | Direct ingestion, high confidence base |
| **Verified** | TAXII feeds from known providers (OTX, CIRCL) | Standard ingestion, medium confidence base |
| **Unverified** | New or community feeds | MARSHAL-gated ingestion, low confidence base, manual review |
| **Blocked** | Feeds with accuracy_ratio < 0.3 | Automatic pause, VIGIL AMBER alert |

Feed trust levels can be changed only by users with the `threatflow_admin` role, and every change is WORM-logged.

---

## Sensitive Data Handling

| Data | Classification | Handling |
|------|---------------|---------|
| IOC values (IPs, domains, hashes) | Internal | Stored in PostgreSQL, not exposed without authentication |
| Feed API keys | Secret | Environment variables only, never logged or serialised |
| CITADEL HMAC secret | Secret | Environment variable, never logged |
| STIX bundles | Internal | Exported only to authenticated consumers, WORM-logged |
| Correlation results | Internal | Cross-platform context — access restricted to ecosystem services |

---

## NIS2 Alignment

ThreatFlow contributes to NIS2 Article 21(2) compliance:

| Measure | Contribution |
|---------|-------------|
| (a) Risk analysis | IOC confidence scoring informs risk assessment |
| (b) Incident handling | IOC context enriches IRFlow incident response |
| (d) Supply chain security | Feed-sourced IOCs identify supply chain threats |
| (e) Network security | Network-level IOCs (IPs, domains) feed firewall rules |
| (h) Cryptography | All WORM events chain-hashed via CITADEL SHA-256 chain |

---

## See Also

- [CITADEL Integration](citadel-integration.md) — MARSHAL governance and WORM logging
- [Deployment](deployment.md) — production security checklist
- [Configuration](configuration.md) — security-sensitive environment variables
- [IOC Feeds](ioc-feeds.md) — feed trust model implementation
- [Architecture](architecture.md) — security controls in the component diagram
