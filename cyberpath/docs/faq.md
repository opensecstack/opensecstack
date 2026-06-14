# CyberPath FAQ

Conceptual questions about what CyberPath is, what it isn't, and how
it fits the opensecstack ecosystem. For symptom-driven debugging,
jump to [troubleshooting.md](troubleshooting.md).

---

## What does CyberPath do?

CyberPath is a security training and certification platform. It
sequences learners through tracks of lessons, quizzes, and hands-on
labs, and it produces immutable, signed, audit-grade evidence of
completion sealed in the CITADEL WORM ledger. The driving use case
is **NIS2 Article 21(2)(g)** — staff cybersecurity training with
documented evidence of completion.

Concretely: you assign a track, the learner walks through it, and
auditors can later verify the completion cryptographically against
the exact lesson revision the learner saw.

---

## What does CyberPath *not* do?

- **It is not a general-purpose LMS.** Generic L&D content (HR
  onboarding, sales training) belongs in Moodle or TalentLMS.
- **It is not a CTF platform.** Lab content is curriculum-anchored;
  capture-the-flag scoring lives in SecureLab.
- **It is not a content marketplace.** Tracks are authored within
  the ecosystem; third-party content can be imported with
  attribution but isn't a primary delivery channel.
- **It is not a real-time proctoring platform.** Certifications are
  evidence of completion against a content version, not proctored
  exam outcomes.

---

## Why Apache 2.0 and not AGPL?

CyberPath is a tool platform — embeddable in proprietary training
pipelines and corporate LMS deployments. Apache 2.0 matches APIGuard,
ThreatFlow, OpenScrub, and SecureLab. CITADEL and VertGuard, where
the goal is to keep the audit-grade core open, ship under AGPL.
CyberPath isn't the audit-grade core — it produces evidence that
flows into one (CITADEL).

---

## Why Wasm not Docker for v1.0.0 labs?

v1.0.0 ships **Docker-based** labs because the technology exists,
the tooling is mature, and shipping value to learners faster matters.

v1.0.0 adds **wasmtime-hosted** labs because:

- Spinup goes from minutes to seconds (Docker p95 ~30s; Wasm p95
  target ≤ 5s)
- Per-session isolation is structurally tighter — no shared kernel,
  no host filesystem access, capability-based imports
- Lab images are pre-built artefacts with SHA-256 checksums; no
  per-tenant Docker daemon attack surface

Docker labs remain supported for content that needs a full Linux
userspace (e.g. Linux hardening). The runtime is per-lab, not
per-deployment.

---

## Can I run a private deployment without CITADEL?

Yes — set `CYBERPATH_CITADEL_API_URL=` and CyberPath starts in
**standalone mode** with a loud WARN. Mutations still execute;
WORM emission becomes a no-op.

This is appropriate for:

- Local development
- Internal pilots without compliance requirements
- Air-gapped environments where CITADEL doesn't make sense

It is **not** appropriate for production use under NIS2. The whole
point of CyberPath is the audit chain; without CITADEL you're
running an LMS with a database row, not audit-grade evidence.

---

## How do I add a new track?

```bash
# 1. Author content
mkdir -p content/tracks/<slug>/{lessons,quizzes,labs}
edit content/tracks/<slug>/track.yaml          # metadata
edit content/tracks/<slug>/lessons/01.sq.md    # shqip source
edit content/tracks/<slug>/lessons/01.en.md    # english translation
edit content/tracks/<slug>/quizzes/01.yaml     # question bank

# 2. Validate locally
cyberpath-cli content validate content/tracks/<slug>/

# 3. Import (idempotent)
cyberpath-cli track import content/tracks/<slug>/track.yaml
```

Authoring conventions are in
[module-list.md § Authoring conventions](module-list.md#authoring-conventions)
and contributing guidance in `../CONTRIBUTING.md`.

---

## Where do certifications get stored?

In Postgres (`certifications` table) and, for v1.0.0+, mirrored to
CITADEL as an immutable evidence event. The certification row
carries:

- The Ed25519 signature over the canonical certification body
- The signing key id (so verifiers know which public key to use)
- The issued / expires timestamps
- The `evidence_hash` linking back to the underlying completions

The signed PDF is **regenerated on demand** from the row — it's not
stored as bytes. This means you can rotate the PDF template
(branding, layout) without breaking the evidence chain.

---

## Is CyberPath multi-tenant?

Yes. Tenant isolation is enforced at:

- **JWT** — every authenticated call carries a `tenant` claim
- **Database** — tenant id columns on every domain table; RLS
  policies in v1.0.0+
- **Lab sandbox** — per-tenant Docker network or Wasm host pool
- **NetworkPolicy (Helm)** — the chart's tenant-aware policies
  prevent cross-tenant lab traffic
- **CITADEL events** — `tenant` field on every emitted event;
  CITADEL's own tenant scoping applies

Single-tenant deployments simply leave the tenant claim empty.

---

## What about offline labs?

The Docker runtime works offline if the lab images are pre-pulled.
The Wasm runtime is offline-friendly by design — lab images are
small (~5–50 MiB), pre-built, and fingerprinted. Air-gapped
deployments mirror the lab-image registry into their own OCI
registry and pin via SHA-256.

Offline tracks (no labs, no external content fetches) work end-to-
end with no internet egress. Authoring is local-only.

---

## Why Go + React not Python?

The same answer as the rest of the ecosystem: Go gives us a single
static binary, predictable memory, fast startup, and a stable
concurrency model. The Go HTTP stack (`chi` + `pgx` + `zerolog`)
matches VertGuard, APIGuard, IRFlow, and OpenScrub — operators
recognise the shape.

React + Vite for the frontend matches the rest of the ecosystem
dashboards, with TanStack Query for API state and xterm.js for the
browser terminal.

The wasmtime sandbox is in **Rust** because wasmtime's Rust
bindings are first-class and the sandbox host is a security-
sensitive component where the Rust trade-off is right.

Python is reserved for ecosystem components where ML matters
(VertGuard's ML side-car). CyberPath has no ML inference path.

---

## How do I integrate with my existing LMS?

Two patterns:

- **CyberPath as the cyber track within Moodle/TalentLMS** —
  embed CyberPath via SSO and present completed CyberPath tracks
  as completed Moodle modules. NIS2 Compass still queries CyberPath
  directly for the audit chain.
- **CyberPath as the audit layer** — keep your existing LMS as the
  course catalogue, mirror completions into CyberPath via a webhook
  or batch job, and rely on CyberPath only for the
  CITADEL evidence emission. The cost is that you lose the lab
  runtime, the bilingual content pipeline, and the immutable content
  versioning — you're using CyberPath as a thin audit shim.

The first pattern is recommended. The second works for incremental
migrations.

---

## Can completions be revoked?

Yes, via a separate `cyberpath.correction` event referencing the
original `completion_id`. The original event remains in the WORM
ledger (CITADEL is append-only by design); the correction is a new
event that supersedes it for query purposes.

Reasons to issue a correction:

- The track was found to contain incorrect material (issued under a
  bad `content_version_id`)
- The completion was fraudulent (account compromise; identity
  challenge)
- A scoring bug under-credited or over-credited the learner

Routine completions are **not** revoked when content changes — the
content_version_id pins the evidence. New content gets new
completions.

---

## What's the data retention policy?

| Data | Default retention |
|---|---|
| `users` | Indefinite while account active; soft-delete on offboard |
| `progress` | Indefinite while account active |
| `completions` | Indefinite (audit evidence) |
| `certifications` | Indefinite (audit evidence) |
| `lab_sessions` | 90 days (operational telemetry) |
| `content_versions` | Indefinite (append-only) |
| Auth refresh tokens | TTL-bounded; denylist purged after expiry |

The audit-chain tables (`completions`, `certifications`,
`content_versions`) are immutable by policy. NIS2 prescribes record
retention; check your local DPA's interpretation but plan for at
least the duration of the certification expiry plus the audit
window (typically 6+ years total).

---

## Does it work without IRFlow?

Yes. IRFlow integration is **optional** and one-way (CyberPath
consumes IRFlow signals to recommend tracks). Leave
`CYBERPATH_IRFLOW_API_URL=` empty and the recommendation feature
falls back to manual track assignment by instructors.

---

## Does it work without NIS2 Compass?

Yes. The coverage and recommend endpoints are still served — they
just won't be polled. Operators querying them directly (curl, BI
tools) still get the full coverage matrix per user.

If you're not running NIS2 Compass, you're probably not running
CyberPath for NIS2 reasons either. Both work standalone for
non-regulatory training programmes.

---

## How is CyberPath licensed?

Apache 2.0, same as APIGuard, ThreatFlow, OpenScrub, and SecureLab.
See `LICENSE` in the project root. Track content under
`content/tracks/` is dual-licensed (Apache 2.0 + CC-BY-SA-4.0); the
content licence is documented per-track in `track.yaml`.

---

## How do I report a security issue?

See [SECURITY.md](../SECURITY.md). **Do not** open a public GitHub
issue for a vulnerability — email `security@opensecstack.org` with
PGP-encrypted contents. Sandbox-escape disclosures from the Wasm
lab runtime (v1.0.0+) are treated as high-severity by default.

---

## Where do I go next?

- New here? Start with [quick-start.md](quick-start.md).
- Building an integration? Read [api.md](api.md) +
  [nis2-integration.md](nis2-integration.md).
- Operating in production? Read [deployment.md](deployment.md) and
  [deployment-helm.md](deployment-helm.md).
- Investigating an incident? Read
  [troubleshooting.md](troubleshooting.md) first.
- Curious about the schema? Read
  [architecture.md § PostgreSQL schema overview](architecture.md#postgresql-schema-overview).

---

## See also

- [quick-start.md](quick-start.md)
- [api.md](api.md)
- [configuration.md](configuration.md)
- [deployment.md](deployment.md)
- [deployment-helm.md](deployment-helm.md)
- [troubleshooting.md](troubleshooting.md)
- [architecture.md](architecture.md)
- [module-list.md](module-list.md)
- [citadel-integration.md](citadel-integration.md)
- [nis2-integration.md](nis2-integration.md)
- [../README.md](../README.md)
- [../ROADMAP.md](../ROADMAP.md)
