# OpenCSIRT Threat Model (STRIDE)

> v1.0.0. STRIDE applied to OpenCSIRT's attack surface. Companion to
> [security-checklist.md](security-checklist.md),
> [pentest-scope.md](pentest-scope.md),
> [pre-audit-plan.md](pre-audit-plan.md), and the project
> [SECURITY.md](../../SECURITY.md).
>
> OpenCSIRT's load-bearing surface is **the federated CSIRT trust
> chain**: peer CSIRTs, NIS2 Compass, ThreatFlow, IRFlow, and
> CITADEL all exchange evidence with OpenCSIRT, and a forged
> message anywhere in that fabric is a primary class of finding.
> The kernel-tier severity tier from OpenScrub does not apply here
> — the equivalent maximum tier in OpenCSIRT is **TLP:RED leak**.

## Trust boundaries

```
   ┌────────────────────────────────────────────────────────────┐
   │ External actors                                            │
   │  · Peer CSIRTs (federated, semi-trusted)                   │
   │  · IRFlow signer (HMAC-trusted)                            │
   │  · Abuse mailbox (untrusted email)                         │
   │  · Constituency members (read-only, JWT)                   │
   └─────────────────────────────┬──────────────────────────────┘
                                 │
                       ─── boundary T1 ───
                                 │
   ┌─────────────────────────────┴──────────────────────────────┐
   │ Inbound webhook layer (HMAC verify, JWT verify)            │
   │  · /api/v1/integrations/irflow/incident                    │
   │  · /api/v1/auth/login                                      │
   │  · /api/v1/* (JWT-gated)                                   │
   └─────────────────────────────┬──────────────────────────────┘
                                 │
                       ─── boundary T2 ───
                                 │
   ┌─────────────────────────────┴──────────────────────────────┐
   │ Go API (port 8088) — chi router, RBAC, services            │
   │ Python advisory subsystem (port 8089) — abuse-mailbox      │
   │   parser, YARA, CSAF templating                            │
   └─────────────────────────────┬──────────────────────────────┘
                                 │
                       ─── boundary T3 ───
                                 │
   ┌─────────────────────────────┴──────────────────────────────┐
   │ Postgres (TLS) + outbound integrations                     │
   │  · CITADEL (HMAC, ±5 min)                                  │
   │  · ThreatFlow (bearer, in-zone)                            │
   │  · NIS2 Compass (in-zone)                                  │
   │  · VertGuard (in-zone, scaffolded)                         │
   │  · Peer CSIRTs (PGP-signed)                                │
   └────────────────────────────────────────────────────────────┘
```

## Attack surface inventory

| # | Surface | Crossing | Adversary capability |
|:-:|---|---|---|
| S1 | Inbound IRFlow webhook | T1 → T2 | crafted body + headers; replay |
| S2 | Outbound CITADEL | T2 → T3 | observe traffic; impersonate receiver |
| S3 | Outbound ThreatFlow / NIS2 / VertGuard | T2 → T3 | as S2; plus credential exposure |
| S4 | Postgres data plane | within T3 | SQL injection, credential theft, RLS gap |
| S5 | JWT auth + 6 roles | T1 → T2 | forge token, escalate role |
| S6 | Python advisory subsystem | T1 (mail) → T2 | malicious abuse mail, YARA bypass, header injection |
| S7 | CSAF advisory tampering | T2 → T2 | mutate draft between save and publish |
| S8 | Peer CSIRT escalation | T2 → T1 (federated) | impersonate peer, abuse trust |

## STRIDE per surface

### S1 — Inbound IRFlow webhook

| # | Threat | Category | Mitigation |
|:-:|---|---|---|
| S1.1 | Forged HMAC | Spoofing | `VerifyHMAC` constant-time compare; `OPENCSIRT_IRFLOW_WEBHOOK_SECRET` rotated 90d |
| S1.2 | Replay of old signed body | Tampering | RFC3339 `X-Timestamp` ±5-minute window enforced in [webhook_hmac.go](../../internal/integrations/webhook_hmac.go) |
| S1.3 | Body > 1 MiB DoS | DoS | `io.LimitReader(r.Body, 1<<20)` cap in `(*IRFlowWebhook).ServeHTTP` |
| S1.4 | Severity injection (`severity:"super"`) | Tampering | switch-case in [irflow.go](../../internal/integrations/irflow.go) defaults to `"medium"` |
| S1.5 | Duplicate `irflow_id` re-delivery | EoP (forced reopen) | application-level dedup on `metadata->>'irflow_id'`; v1.1 will add a unique JSONB index |
| S1.6 | Unbounded `metadata` blob | DoS (DB bloat) | downstream JSONB column has no per-key bound; mitigation deferred to operator-side rate-limit |
| S1.7 | Forged `X-Timestamp` (clock skew) | Spoofing | RFC3339 strict parse; chrony on both ends required by checklist |
| S1.8 | Unsigned plaintext call | Spoofing | route refuses without `X-Signature` header; `VerifyHMAC` returns error on missing |
| S1.9 | Body charset confusion | Tampering | `json.Unmarshal` on raw bytes; no charset transcoding |
| S1.10 | Audit-log gap on rejected webhook | Repudiation | WARN log includes reason; `audit_log` row written on accept |

### S2 — Outbound CITADEL

| # | Threat | Category | Mitigation |
|:-:|---|---|---|
| S2.1 | Spoofed CITADEL receiver | Spoofing | `OPENCSIRT_CITADEL_API_URL` operator-config; HMAC means response is informational only |
| S2.2 | HMAC secret leak | Spoofing | rotation slot in `hmacSecrets [][]byte`; 90-day rotation; never logged |
| S2.3 | Replay of stale event | Tampering | CITADEL ±5 min server-side; `(*Client).deliver` re-stamps `ts` per attempt |
| S2.4 | Outbox tampering in DB | Repudiation | `citadel_outbox` rows are evidence, but the WORM truth is on the CITADEL side; mismatch is detectable |
| S2.5 | Confirmation channel poisoning | EoP | `Confirmations()` channel private to package; only the watcher consumes |
| S2.6 | Unbounded retry buffer | DoS | `c.queue` capped at 1024; overflow drops with `SubmitDropped` |
| S2.7 | DryRun in prod | Repudiation | checklist gate requires `OPENCSIRT_CITADEL_DRY_RUN=false` |
| S2.8 | Empty `hmacSecrets` slice | EoP (silent unsigned send) | `(*Client).deliver` returns `errors.New("citadel: no hmac secrets configured")` before HTTP |
| S2.9 | Crash mid-send leaves orphan `sending` | Availability | `RequeueSending` on watcher boot |
| S2.10 | Wrong `X-Key-ID` after rotation | Availability | dual-secret slot; old key accepted during overlap |

### S3 — Outbound ThreatFlow / NIS2 / VertGuard

| # | Threat | Category | Mitigation |
|:-:|---|---|---|
| S3.1 | Bearer token leak (when v1.1 adds it) | Spoofing | secret-manager mount; never `env: value:` |
| S3.2 | TLS-strip on outbound | Tampering | Tier-2 deployment uses mesh mTLS; Tier-1 trusts the docker network |
| S3.3 | NIS2 endpoint impersonation | Spoofing | URL operator-config; bearer in v1.1; mTLS in Tier-2 |
| S3.4 | ThreatFlow receiver returns 200 but drops | Repudiation | OpenCSIRT does not roll back on push failure; CITADEL `advisory_published` is the canonical record |
| S3.5 | VertGuard publisher impersonation | Tampering | subscriber dedups on `vertguard_advisory_id`; payload treated as untrusted metadata |
| S3.6 | Oversized response (>4 / 16 MiB) | DoS | `io.LimitReader` caps in `vertguard.go` and `threatflow.go` |
| S3.7 | Slow-loris on outbound | DoS | per-client timeouts (`http.Client{Timeout: …}`) of 15–30s |
| S3.8 | Credential reused across platforms | EoP | per-source secrets enforced by `.env.example` separation |
| S3.9 | NIS2 below-threshold leak | Information Disclosure | `Notify` rejects severity ∈ {low, medium} before serialising |
| S3.10 | Constituency_id substitution | Tampering | typed `*uuid.UUID`; serialised verbatim from incident row |

### S4 — Postgres data plane

| # | Threat | Category | Mitigation |
|:-:|---|---|---|
| S4.1 | SQL injection on incident filters | Tampering | `pgx` parameterised everywhere; semgrep `no raw sql` |
| S4.2 | Credential theft from env | Spoofing | secret-manager + `secretKeyRef`; rotation 180d |
| S4.3 | Cross-row read by analyst | InfoDisc | RBAC at app layer; checklist explicitly disables RLS dual-enforcement |
| S4.4 | TLP:RED draft visible to wrong role | InfoDisc | publish endpoint requires `csirt_lead`+; draft list filters by TLP+role |
| S4.5 | DELETE on `audit_log` | Repudiation | DB grant audit; CITADEL WORM mirror is the canonical truth |
| S4.6 | `metadata` JSONB injection | Tampering | column is JSONB-typed; no string concatenation |
| S4.7 | Backup leak | InfoDisc | encrypted-at-rest checklist; 30d retention |
| S4.8 | Pre-publish draft exfil | InfoDisc | `advisories.state='draft'` rows only readable by analyst+; CSAF body in JSONB |
| S4.9 | Connection pool exhaustion | DoS | `max_open_conns` bound; readiness gate |
| S4.10 | Migration drift | EoP | `migrations/` checked in; CI verifies forward+back |

### S5 — JWT auth + 6 roles

| # | Threat | Category | Mitigation |
|:-:|---|---|---|
| S5.1 | `none`/RS256 algorithm confusion | Spoofing | jwt v5 parser; HS256 hard-coded in `(*Authenticator).Login`; `Verify` rejects mismatched alg |
| S5.2 | Role escalation via JWT mutation | EoP | HMAC over header+payload; `c.Role.Valid()` re-checked in `Verify` |
| S5.3 | `external_peer` reads internal incident | InfoDisc | rank table places `external_peer` between viewer and analyst; handlers gate on `RoleAtLeast(RoleAnalyst)` |
| S5.4 | `analyst` publishes advisory | EoP | `RequireRole(RoleCSIRTLead)` middleware on publish handler |
| S5.5 | `viewer` mutation | EoP | rank=1; any handler with `RequireRole(RoleAnalyst)`+ blocks |
| S5.6 | Long-lived token after role change | EoP | TTL default 12h; rotation-secret slot invalidates older sigs |
| S5.7 | Login enumeration via timing | InfoDisc | `subtle.ConstantTimeCompare` on password hash |
| S5.8 | Pepper leak | Spoofing | `pepper` env-only; never logged; sha256 over `pepper||password` |
| S5.9 | JWT secret leak (single key) | Spoofing | `secrets [][]byte` slice supports rotation; sign with `[0]` |
| S5.10 | Empty user store in prod | EoP | `ErrIssuerDisabled` on `Login` if `len(users) == 0` |

### S6 — Python advisory subsystem (port 8089)

| # | Threat | Category | Mitigation |
|:-:|---|---|---|
| S6.1 | Header injection from abuse mail (`Subject: …\nBcc: attacker`) | Tampering | parser strips CR/LF before forwarding to CSAF templater |
| S6.2 | YARA rule poisoning | EoP | rules pinned to upstream commit; checklist requires monthly review |
| S6.3 | YARA-bypass payload | Tampering | YARA is one of several signals; CSAF draft requires `csirt_lead` review before publish |
| S6.4 | XXE in attachment XML | InfoDisc | parser disables external entities (`defusedxml`) |
| S6.5 | Zip-bomb attachment | DoS | size cap + nested-depth cap on extraction |
| S6.6 | Unicode-confusable subject | Tampering | NFKC normalisation in parser; raw subject preserved alongside |
| S6.7 | SSRF via embedded link | InfoDisc | parser does not fetch links; only extracts |
| S6.8 | Python advisory exposed to internet | EoP | NetworkPolicy in checklist restricts :8089 to API pod only |
| S6.9 | CSAF injection (template attack) | Tampering | Jinja2 autoescape on; values validated against CSAF 2.0 schema before persist |
| S6.10 | Abuse-mail loop | DoS | sender-deduplication window in parser |

### S7 — CSAF advisory tampering between draft and publish

| # | Threat | Category | Mitigation |
|:-:|---|---|---|
| S7.1 | Draft mutated by analyst before lead approval | EoP | publish requires `csirt_lead`+; CITADEL `advisory_published` event includes the body fingerprint |
| S7.2 | TLP downgraded silently | InfoDisc | TLP enum CHECK constraint; downgrade requires explicit field in publish request |
| S7.3 | Body swap at publish time | Tampering | body hash recorded at draft-approval time; publish verifies match |
| S7.4 | Republish of withdrawn advisory | Repudiation | `state` machine: `withdrawn` is terminal; new advisory required |
| S7.5 | csaf_id collision | Tampering | `csaf_id text NOT NULL UNIQUE` |
| S7.6 | Unbounded csaf_doc JSONB | DoS | per-row size cap at insert |
| S7.7 | Race: two leads publish concurrently | EoP | row-level lock on advisory id during publish |
| S7.8 | Draft visibility to constituency | InfoDisc | list query filters `state IN ('published')` for non-analyst |
| S7.9 | Audit gap on withdraw | Repudiation | `POST /api/v1/advisories/{id}/withdraw` implemented in v1.0; state change recorded in `audit_log`. `advisory_withdrawn` CITADEL event deferred to v1.1. |
| S7.10 | Outbound ThreatFlow push of un-redacted draft | InfoDisc | push only on `state='published'`; gated in handler |

### S8 — Peer CSIRT escalation (federation trust)

| # | Threat | Category | Mitigation |
|:-:|---|---|---|
| S8.1 | Impersonation of peer CSIRT | Spoofing | PGP key in `peer_csirts.pgp_key`; checklist requires out-of-band verification |
| S8.2 | TLP:RED escalated to TLP:CLEAR-only peer | InfoDisc | G3 in [pre-audit-plan.md](pre-audit-plan.md) is the test; runtime guard in escalation handler |
| S8.3 | Replay of escalation acknowledgement | Tampering | `escalations` UNIQUE on `(incident_id, peer_id)` — no duplicate row |
| S8.4 | Adversary registers as peer | EoP | peer creation requires `admin`; PGP verified out-of-band |
| S8.5 | `pgp_key` column trusted blindly | Spoofing | checklist explicitly forbids trusting the column without OOB verification |
| S8.6 | Unsolicited inbound from "peer" | Spoofing | no inbound webhook in v1.0; peers are recipients only |
| S8.7 | Compromised peer leaks shared incident | InfoDisc | residual; peer trust contract documents the constituency expectation |
| S8.8 | Stale peer endpoint (DNS hijack) | Tampering | TLS verification required on peer endpoint URL |
| S8.9 | Escalation reason field leaks PII | InfoDisc | reason is operator-authored; checklist note on PII minimisation |
| S8.10 | Audit gap on escalation | Repudiation | every escalation emits `opencsirt.escalation_sent` (CITADEL WORM) |

## Out of model

- Operator workstation compromise — out of scope; addressed by org-level
  ISMS.
- Postgres internals (DBA-level attacks) — operator's responsibility.
- Downstream platforms (CITADEL, NIS2 Compass, ThreatFlow internals) —
  separate threat models in their own repositories.
- Side-channel attacks against the API container from a co-tenant —
  Tier-2 deployment expects a dedicated node pool.

## Compliance traceability

| Threat row | NIS2 21(2) measure | Evidence |
|---|---|---|
| S1.* (webhook) | (b) incident handling | `audit_log` + CITADEL `incident_opened` |
| S2.* (CITADEL) | (h) cryptography, (c) BCM | HMAC + outbox + WORM mirror |
| S5.* (auth) | (i) access control | RBAC + JWT + `RequireRole` |
| S6.* (advisory subsystem) | (b), (h) | YARA rules, CSAF schema validation |
| S8.* (peer trust) | (b), Article 11 | PGP-verified peer registry; `opencsirt.escalation_sent` |

## Related

- [security-checklist.md](security-checklist.md) — control evidence per row
- [pentest-scope.md](pentest-scope.md) — what we hand the auditor
- [pre-audit-plan.md](pre-audit-plan.md) — gap closure
- [compliance-map.md](compliance-map.md) — Article 11 + 23 mapping
- [../../SECURITY.md](../../SECURITY.md) — disclosure tiers
