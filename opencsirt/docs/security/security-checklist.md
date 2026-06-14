# OpenCSIRT Security Checklist

> Tactical hardening checklist for operators deploying OpenCSIRT
> v1.0.0. Tick each box on the path from `git clone` to a production
> rollout. Companion to
> [threat-model.md](threat-model.md), [pre-audit-plan.md](pre-audit-plan.md),
> and [pentest-scope.md](pentest-scope.md).
>
> OpenCSIRT's security posture is dominated by **federated CSIRT
> trust** and **TLP-tagged data confidentiality**: peer CSIRTs share
> incidents under the Traffic Light Protocol, and a mis-routed
> TLP:RED advisory is the highest-tier incident this platform can
> produce.

## 1. PostgreSQL

- [ ] `sslmode=require` (or `verify-full`) in
      `OPENCSIRT_DB_URL`. Plain TCP refused by the production gate.
- [ ] **Row-level security off.** OpenCSIRT enforces tenancy at the
      app layer (`internal/auth/`). Dual-enforcement makes audit
      harder, not easier — see [threat-model.md § S4](threat-model.md).
- [ ] DB user least-privilege: SELECT/INSERT/UPDATE on the
      OpenCSIRT schema only, no SUPERUSER, no `pg_read_server_files`.
- [ ] **Backup retention 30 days**, encrypted at rest, restored
      once per quarter into a throwaway namespace.
- [ ] Encrypted at rest at the disk/volume layer (LUKS, cloud KMS).
- [ ] Indices verified — `idx_incidents_status_opened`,
      `idx_advisories_state`, `idx_citadel_outbox_state_created`
      all exist (see [migrations/0001_init.up.sql](../../migrations/0001_init.up.sql)).
- [ ] `audit_log` table append-only at DB level — no UPDATE/DELETE
      grants for the application role.

## 2. Secrets

- [ ] **Never commit `values.yaml` or `.env` with real credentials.**
      The repo ships `values.yaml.example` and `.env.example`; the
      real ones live outside the repo (Sealed Secrets, External
      Secrets Operator, or an external KMS reference).
- [ ] `OPENCSIRT_JWT_SECRET` is **≥32 bytes** of CSPRNG output.
      Rotate **quarterly**. Rotation is online: the dual-secret
      slot in `auth.New(secrets [][]byte, …)` keeps existing tokens
      valid for one TTL window after the cut-over.
- [ ] `OPENCSIRT_CITADEL_HMAC_SECRETS` rotated **quarterly with a
      24-hour overlap** — new key first, old key second. The slice
      shape `[][]byte` in `(*Client).hmacSecrets` makes overlap a
      single env-var change.
- [ ] `OPENCSIRT_IRFLOW_WEBHOOK_SECRET` rotated alongside the IRFlow
      side; both must match at all times.
- [ ] `OPENCSIRT_PASSWORD_PEPPER` set to **≥32 bytes** of CSPRNG
      output; rotation requires re-hashing all user records.
- [ ] DB password lives in a K8s Secret, mounted via `secretKeyRef`
      — never `env: value:`. Rotation cadence 180d.
- [ ] Use **Sealed Secrets, External Secrets Operator, or external
      KMS** — not raw K8s Secrets in git.
- [ ] Logs reviewed: `grep -ri "secret\|token\|password\|hmac"
      /var/log/opencsirt*` returns nothing meaningful.
- [ ] PGP key for `security@opensecstack.org` published, so a
      reporter can reach you for a TLP:RED finding without
      exposing details over plain email.

## 3. Image hardening

- [ ] API image: **distroless**
      (`gcr.io/distroless/base-debian12:nonroot`) or scratch. No
      shell in the production image.
- [ ] Web image: nginx-distroless or static `httpd`-style; no
      busybox shell behind it.
- [ ] Python advisory image: `python:3.12-slim` with
      `PYTHONDONTWRITEBYTECODE=1`; no compiler, no package manager
      at runtime.
- [ ] Containers run **non-root** (UID 65532) with no caps.
- [ ] `securityContext.allowPrivilegeEscalation=false`.
- [ ] `securityContext.readOnlyRootFilesystem=true` on every pod.
- [ ] Drop `ALL` capabilities (`securityContext.capabilities.drop:
      ["ALL"]`).
- [ ] seccomp `RuntimeDefault` on every pod.
- [ ] No SSH, no agent, no diagnostic shell in any production image.

## 4. Network policies

- [ ] **API listens on `:8088` internal only.** Ingress firewalls /
      `NetworkPolicy` restrict it to the dashboard pod and
      authenticated operators (jump host or VPN).
- [ ] **Python advisory subsystem on `:8089` is API-only.**
      `NetworkPolicy` permits only the OpenCSIRT API pod to reach
      it. Direct internet exposure is a policy violation —
      threat-model row [S6.8](threat-model.md).
- [ ] Web dashboard on `:3088` behind the public ingress.
- [ ] `/metrics` (Prometheus) **not exposed publicly**. Restrict
      via `NetworkPolicy` to the Prometheus scraper.
- [ ] Default-deny egress on the API pod. Allow only: Postgres,
      CITADEL URL, ThreatFlow URL, NIS2 Compass URL, IRFlow URL,
      VertGuard URL (when configured), peer CSIRT endpoints.
- [ ] CORS `allowed_origins` reviewed before each release. Default
      is empty (operator must configure).

## 5. Audit

- [ ] **CITADEL emission enabled in production.**
      `OPENCSIRT_CITADEL_DRY_RUN=false` is mandatory in prod —
      verify with the audit fire-test below. DryRun=true is the
      dev default precisely so a developer doesn't pollute the
      WORM stream.
- [ ] Both `OPENCSIRT_CITADEL_API_URL` and
      `OPENCSIRT_CITADEL_HMAC_SECRETS` set in prod.
- [ ] CITADEL outbox depth alerted at sustained > 10 000. A growing
      outbox means CITADEL is unreachable; investigate before drops.
- [ ] **Audit fire-test pre-release:** open an incident, observe
      the `opencsirt.incident_opened` event in the CITADEL WORM
      API; close it, observe the matching `_closed` event; publish
      a draft advisory, observe `_published`; escalate to a peer,
      observe `_sent`. All four event types verified per release.
- [ ] `audit_log` table grants verified — no UPDATE/DELETE for the
      app role; INSERT-only.

## 6. Federation & TLP

- [ ] **PGP keys for peer CSIRTs verified out-of-band.** The
      `peer_csirts.pgp_key` column is **not** trusted on its own
      — admin must confirm fingerprint via a secondary channel
      (in-person, signed letter, video call) before flipping
      `last_handshake_at`. Threat-model row [S8.5](threat-model.md).
- [ ] TLP:RED advisories never propagate to peers marked
      TLP:CLEAR-only. This is **G3 in
      [pre-audit-plan.md](pre-audit-plan.md)**; until G3 closes,
      operators must review every escalation manually.
- [ ] Peer endpoint URLs use HTTPS with verified certs (no
      `InsecureSkipVerify`).
- [ ] Peer registry changes require `admin` role.
- [ ] CSIRTs Network / FIRST.org membership recorded for each
      peer (where applicable) for audit.

## 7. Auth & roles

- [ ] **Six roles configured correctly:** `viewer`, `external_peer`,
      `analyst`, `operator`, `csirt_lead`, `admin`. Rank verified
      by `auth_test.go`.
- [ ] `csirt_lead` role assigned narrowly — only operators
      authorised to publish advisories. Cross-author/approver
      separation is socially enforced in v1.0.0; CITADEL Gate-3
      NDS in a future v1.x.
- [ ] `external_peer` users granted only when an out-of-band peer
      handshake exists.
- [ ] JWT TTL ≤ 12h (default).
- [ ] Failed-login lockout configured (5 fails / 15 min).

## 8. Python advisory subsystem (port 8089)

- [ ] **YARA rules pinned to a known-good upstream commit**, not
      `master` / `latest`. Review monthly.
- [ ] YARA rule additions go through a 2-reviewer rule (CODEOWNERS).
- [ ] `defusedxml` used in any XML parsing path.
- [ ] Attachment size cap and nested-depth cap on archive
      extraction (zip-bomb mitigation).
- [ ] Unicode normalisation (NFKC) in subject/body parser.
- [ ] Header injection regression test in CI (CR/LF stripping).
- [ ] Subsystem logs do not contain raw inbound mail bodies.

## 9. Supply chain

- [ ] Image tags **pinned by digest** in production manifests, not
      by tag (`@sha256:…`).
- [ ] `cosign verify` passes against the
      `ghcr.io/opensecstack/opencsirt:1.0.0` bundle pre-deploy.
- [ ] SBOM (CycloneDX) attached to each image attestation.
- [ ] `govulncheck` clean in CI on `main`.
- [ ] `pip-audit` clean on the Python advisory subsystem.
- [ ] `npm audit --audit-level=moderate` clean on `web/`.
- [ ] Helm chart pins all dependent images by digest.

## 10. Pre-release gates

- [ ] All boxes above ticked or formally accepted with rationale in
      [pre-audit-plan.md § Gap closure log](pre-audit-plan.md).
- [ ] `make test-integration` green: docker-compose stack up,
      IRFlow webhook fired, CITADEL outbox drained.
- [ ] [SECURITY.md](../../SECURITY.md) disclosure SLA aligned with
      [threat-model.md](threat-model.md) tiers.
- [ ] Runbook walked through in tabletop including:
      - TLP:RED leak detection (G3)
      - peer CSIRT impersonation
      - CITADEL outbox saturation
      - abuse-mail spike

## Related

- [threat-model.md](threat-model.md)
- [pre-audit-plan.md](pre-audit-plan.md) — gap-closure timeline
- [pentest-scope.md](pentest-scope.md) — what we hand the auditor
- [compliance-map.md](compliance-map.md) — NIS2 / FIRST.org / ENISA mapping
- [../../SECURITY.md](../../SECURITY.md) — disclosure tiers
