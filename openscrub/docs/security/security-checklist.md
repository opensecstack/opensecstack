# OpenScrub Security Checklist

> Tactical hardening checklist for operators deploying OpenScrub
> v1.0.0. Tick each box on the path from `git clone` to a production
> rollout. Companion to
> [threat-model.md](threat-model.md), [pre-audit-plan.md](pre-audit-plan.md),
> and [pentest-scope.md](pentest-scope.md).

OpenScrub's security posture is dominated by the **kernel attack
surface**: the loader holds `CAP_BPF` + `CAP_NET_ADMIN`, attaches an
XDP program at NIC ingress, and writes to BPF maps that decide
`XDP_DROP` / `XDP_PASS` in-kernel. Every item below is scoped against
that fact — defaults that are merely fine for a stateless web app
are not fine for a kernel-touching one.

## 1. Kernel

- [ ] Linux **5.15+** on every node that runs the loader. The loader
      refuses to start on older kernels (CO-RE relocations and BTF
      requirements). 6.1 LTS is recommended.
- [ ] `sysctl net.core.bpf_jit_enable=1` — required for line-rate XDP.
      Without JIT, the verifier-validated program is interpreted and
      throughput collapses.
- [ ] `sysctl kernel.unprivileged_bpf_disabled=1` — non-root processes
      MUST NOT be able to load BPF programs on this host. Defence
      against a co-tenant compromise pivoting through `bpf(2)`.
- [ ] `sysctl net.core.bpf_jit_harden=2` — JIT spray hardening enabled.
- [ ] `sysctl kernel.kptr_restrict=2` and `kernel.dmesg_restrict=1` —
      pointer disclosure / dmesg gating.
- [ ] BTF available (`/sys/kernel/btf/vmlinux` exists) — required by
      Aya for CO-RE relocation. RHEL/CentOS pre-9 may need a backport.
- [ ] Kernel CVE feed subscribed (kernel.org `linux-cve-announce` +
      distro security list). Threat-model item #5 (BPF verifier
      bypass) is residual; rapid patching is the control.

## 2. Capabilities & privilege

- [ ] Loader pod / container has **only** `CAP_BPF` and
      `CAP_NET_ADMIN`. **No `CAP_SYS_ADMIN`** (kernel ≥5.8 split this
      out specifically so XDP loaders can stop carrying the giant
      hammer). Verify with `getpcaps` inside the running container.
- [ ] **Never `privileged: true`** on the loader. The
      `deploy/docker-compose.yml` comment is load-bearing — privileged
      also disables seccomp + AppArmor, which we rely on (see
      [threat-model.md](threat-model.md) #4).
- [ ] API container runs **non-root** (UID 65532) with no caps.
- [ ] Web container runs **non-root** with no caps. The nginx that
      serves the SPA must not have CAP_NET_BIND_SERVICE — bind to a
      high port and let the ingress front it.
- [ ] `securityContext.allowPrivilegeEscalation=false` on every pod
      EXCEPT the loader (which legitimately holds caps).
- [ ] `securityContext.readOnlyRootFilesystem=true` on API + web. The
      loader needs `/sys/fs/bpf` mount but root FS still RO.
- [ ] seccomp `RuntimeDefault` on every pod. The loader pod
      additionally pins to a hardened profile that allowlists `bpf(2)`
      explicitly — do not silently widen this.

## 3. Image hardening

- [ ] API image: **distroless** (`gcr.io/distroless/base-debian12:nonroot`)
      or scratch. No shell in the production image.
- [ ] Web image: nginx-distroless or static `httpd`-style; no busybox
      shell behind it.
- [ ] Loader image: minimal Debian/Alpine with the Aya binary and
      nothing else. No package manager, no compiler, no curl.
- [ ] `docker history` shows zero `apt-get install` lines beyond the
      base image. Anything dynamic is built upstream and copied in.
- [ ] No SSH, no agent, no diagnostic shell.

## 4. Secrets

- [ ] **Never commit `values.yaml` with real credentials.** The repo
      ships `values.yaml.example`; the real one lives outside the
      repo (Sealed Secrets, External Secrets Operator, or an external
      KMS reference).
- [ ] `OPENSCRUB_JWT_SECRET` is **≥32 bytes** of CSPRNG output.
      Rotate **quarterly**. Rotation is online: dual-secret slot
      means existing tokens stay valid for one TTL window after the
      cut-over.
- [ ] `OPENSCRUB_CITADEL_HMAC_SECRET` rotated on the same cadence as
      the upstream CITADEL deployment (90-day default).
- [ ] `OPENSCRUB_THREATFLOW_TOKEN` is a service token, scoped to the
      malicious-IP feed only, and revocable from the ThreatFlow side.
- [ ] DB password lives in a K8s Secret, mounted via `secretKeyRef`
      — never via `env: value:`. Rotation cadence 180d.
- [ ] Logs reviewed: `grep -ri "secret\|token\|password"
      /var/log/openscrub*` returns nothing meaningful.
- [ ] PGP / age key for `security@opensecstack.org` published, so a
      reporter can reach you for a kernel-tier finding without
      exposing details over plain email.

## 5. Network policies

- [ ] **API listens on `:8087`** internal only. Ingress firewalls /
      `NetworkPolicy` restrict it to the dashboard pod and
      authenticated operators (jump host or VPN).
- [ ] `/metrics` (Prometheus) **not exposed publicly**. Bind to a
      private interface or restrict via `NetworkPolicy` to the
      Prometheus scraper.
- [ ] **Only the loader pod uses `hostNetwork: true`.** API and web do
      not. The loader needs hostNetwork because XDP attach happens at
      a host-level NIC, not the pod's veth.
- [ ] Default-deny egress on the API pod. Allow only: Postgres,
      CITADEL URL, ThreatFlow URL, IRFlow URL (when configured).
- [ ] Default-deny egress on the loader pod. The loader has no
      reason to dial out — its only network is the data plane it is
      filtering.
- [ ] CORS `allowed_origins` reviewed before each release. Default is
      empty (operator must configure).

## 6. PostgreSQL

- [ ] `ssl_mode=require` (better: `verify-full`) in
      `OPENSCRUB_DB_URL`. Plain TCP is refused by the production gate.
- [ ] **Row-level security off.** OpenScrub is single-tenant in
      v1.0.0; tenant isolation is enforced at the application's RBAC
      layer (`internal/auth/`) — we do not duplicate that into RLS,
      because dual-enforcement makes audit harder, not easier. If
      multi-tenant lands in v2.x, RLS is the layer to add then.
- [ ] DB user is least-privilege: SELECT/INSERT/UPDATE on the
      OpenScrub schema only, no SUPERUSER, no `pg_read_server_files`.
- [ ] Backups: nightly logical dump + weekly physical (pgBackRest or
      equivalent), encrypted at rest, restored once per quarter into a
      throwaway namespace to verify the procedure.
- [ ] Mitigation table indices verified — `idx_mitigations_started`
      exists. Without it, the IRFlow trigger query
      (`started_at < now() - interval '5 minutes' AND ended_at IS NULL`)
      degrades to a sequential scan as the table grows.

## 7. Audit

- [ ] **CITADEL emission enabled in production.** It is off-by-default
      in dev (no `OPENSCRUB_CITADEL_API_URL` set) precisely so a
      developer doesn't pollute the WORM stream. Production must set
      both `OPENSCRUB_CITADEL_API_URL` and
      `OPENSCRUB_CITADEL_HMAC_SECRET` — verify with the audit fire-test
      below.
- [ ] CITADEL outbox depth alerted at sustained > 10000 (default
      `OPENSCRUB_CITADEL_OUTBOX_MAX=1M`). A growing outbox means
      CITADEL is unreachable; investigate before the buffer drops
      events.
- [ ] **Audit fire-test pre-release:** create a rule, observe the
      `openscrub.rule_change` event in the CITADEL WORM API, withdraw
      the rule, observe the matching `withdraw` event. Cross-check
      `correlation_id` round-trips.
- [ ] `audit_log` Postgres table is append-only at the DB level —
      verify no `UPDATE` or `DELETE` grants on it for the application
      role.

## 8. Supply chain

- [ ] Image tags are **pinned by digest** in production manifests, not
      by tag (`@sha256:…`, not `:1.0.0`). Tags can be re-pushed; digests
      cannot.
- [ ] `cosign verify` passes against the `ghcr.io/opensecstack/openscrub:1.0.0`
      bundle before deploy. The keyless-signing identity matches the
      release workflow's OIDC subject — pattern documented in
      cyberpath/docs/security/image-signing.md (see `cyberpath/docs/security/image-signing.md`).
- [ ] SBOM (CycloneDX) attached to each image attestation; reviewed
      pre-release for known-bad transitive deps.
- [ ] `govulncheck` clean in CI on `main`.
- [ ] `cargo audit` and `cargo geiger` clean on `rust/dataplane/`.
      `cargo geiger` quantifies `unsafe` usage — the loader target is
      zero `unsafe` outside the documented `loader_linux.rs` ABI
      mirrors.
- [ ] `npm audit --audit-level=moderate` clean on `web/`.
- [ ] Helm chart pins all dependent images (Postgres, Prometheus) by
      digest. A drive-by `:latest` is treated as a release blocker.

## 9. Pre-release gates

- [ ] All boxes above ticked or formally accepted with rationale in
      [pre-audit-plan.md § Gap closure log](pre-audit-plan.md).
- [ ] Live-kernel integration tests green on the kernel matrix
      (5.15, 6.1, 6.6).
- [ ] `make test-integration` green: docker-compose stack up, hping3
      packets fired, drop counter matches expectations.
- [ ] [SECURITY.md](../../SECURITY.md) disclosure SLA times match the
      tier table in [threat-model.md § High-tier kernel surface](threat-model.md).
- [ ] Runbook walked through in tabletop including:
      - rule-poisoning detection (huge `/8` block lands in CITADEL)
      - loader crash-loop detection
      - ThreatFlow upstream compromise (allowlist guard fires)

## Related

- [threat-model.md](threat-model.md)
- [pre-audit-plan.md](pre-audit-plan.md) — gap-closure timeline
- [pentest-scope.md](pentest-scope.md) — what we hand the auditor
- [compliance-map.md](compliance-map.md) — NIS2 / framework mapping
- [../../SECURITY.md](../../SECURITY.md) — disclosure tiers
