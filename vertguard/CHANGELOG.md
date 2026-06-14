# VertGuard Changelog

All notable changes to VertGuard are documented here.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

For the ecosystem-wide changelog, see [../CHANGELOG.md](../CHANGELOG.md).

---

## [Unreleased]

### Added

- sinauth SSO integration — authenticate via the SIN identity provider (OAuth 2.0 / OIDC, authorization_code + PKCE); web dashboard added a sinauth.ts client and /auth/callback route.

---

## [1.0.0] - 2026-05-10

### Phase 4.3 — Real-time AI Threat Detection (v1.0.0 stable)

#### Video Deepfake Detection
- `POST /api/v1/video/session` + `WS /api/v1/video/stream/{session_id}` — bidirectional WebSocket stream
- Python `VideoModel`: GradientBoosting on 513-dim feature vector (face_detected + 512-dim CLIP embedding)
- Temporal smoothing: `0.7 × current_frame + 0.3 × rolling_mean` (deque maxlen=30 per session)
- Dashboard `VideoScan` page with live confidence bars and rolling 10-frame history
- Training config: FaceForensics++ + DFDC datasets

#### Voice Clone Detection
- `POST /api/v1/audio/score` — audio fingerprint scoring; `voice_clone_risk: true` at confidence ≥ 0.55
- `ScoreAudio` gRPC RPC added to `InferenceService` proto contract
- Python `AudioModel`: GradientBoosting on MFCC + spectral hash signals from Rust `audio-fingerprint` crate
- `AudioEnricher` Go adapter; hand-written proto bindings follow existing pb pattern
- Training config: ASVspoof2019 + VCTK synthesis datasets

#### Meeting Platform Plugins (Zoom / Teams / WebEx)
- `GET /api/v1/integrations/meetings/connect/{platform}` — OAuth2 authorize redirect
- `GET /api/v1/integrations/meetings/callback` — OAuth2 code exchange (SDK provisioning required)
- `POST /api/v1/integrations/meetings/webhook/{platform}` — HMAC-validated event receiver
- `GET /api/v1/integrations/meetings/status` — platform connection status
- Zoom + WebEx HMAC-SHA256 webhook validation; Teams stubbed pending Azure Bot Framework JWT
- Env config: `VERTGUARD_MEETING_{ZOOM,TEAMS,WEBEX}_{CLIENT_ID,CLIENT_SECRET,WEBHOOK_SECRET}`

#### Security Audit — All gaps closed (100%)
- **1.4** mTLS API↔ML: Istio `PeerAuthentication` (STRICT) + Linkerd `ServerAuthorization` (`deploy/helm/` + `deploy/linkerd/`)
- **5.6** Helm secret gate: OPA Gatekeeper `NoSecretCreateInProd` ConstraintTemplate
- **7.3** `go mod tidy --check` added to CI + `Makefile` target
- **10.5** Public status page: cstate config + GitHub Actions 5-min availability cron
- **10.6** Tabletop runbook: `docs/security/tabletop-runbook.md` (5 scenarios, 230 lines)
- Threat model updated with TB-10/11/12 and AT-4/AT-5 for Phase 4.3 surface

---

### Phase 4.2 — Python ML Layer (v0.5.0 beta)

#### Media Deepfake Detection (Module 1 ML)
- `MediaModel`: `GradientBoostingClassifier` on C2PA metadata signals; no raw pixels transmitted
- C2PA overrides: valid manifest → cap 0.15; invalid manifest → floor 0.70
- `MediaEnricher` Go adapter; `mediaH.ML` wired in server bootstrap

#### Identity Fraud Detection (Module 5 ML)
- `IdentityModel`: `IsolationForest` anomaly detector on 8-dim privacy-safe signal vector
- Country risk scores from FATF grey/black list; hard floors: replay ≥ 3 → 0.80
- `IdentityAdapter` wired in server bootstrap with nil-guard against typed-nil panic
- Training configs: `training/configs/media_clip.yaml`, `training/configs/identity_gan.yaml`

---

### Phase 4.1 — Core Platform (v0.1.0 alpha)

#### Modules
- **Module 3 (Prompt Injection):** `POST /api/v1/prompt/scan` — regex + optional ML; OWASP LLM Top 10 coverage
- **Module 4 (AI Threat Feed):** `GET /api/v1/threatfeed/iocs`, `POST /api/v1/threatfeed/atlas`, MITRE ATLAS mapping
- **Module 1 (Media/C2PA):** `POST /api/v1/media/verify`, `GET /api/v1/media/scans/{id}` — C2PA provenance via Rust `c2pa-rs`; `--certs` flag implemented; 1×1 JPEG test fixture
- **Module 2 (AI Phishing):** `POST /api/v1/phishing/scan` — rule-based + ML enricher
- **Module 6 (Identity):** `POST /api/v1/identity/verify` — claim verification + replay window

#### Infrastructure
- 28 HTTP endpoints across all modules + admin + webhooks
- CITADEL WORM evidence emission wired into all scan handlers
- VG-006 persistent IOC store + community feed puller
- VG-015 persistent webhook subscribers with 3-slot HMAC rotation
- JWT auth with multi-secret rotation + access token denylist (`POST /api/v1/auth/logout`)
- Per-route rate limiters (global 120/min, auth 20/min, scan 60/min)
- Trusted proxy support with `X-Forwarded-For` depth-based stripping + `X-Real-IP` fallback

#### Dashboard (React)
- Login, Dashboard (health), Scan, ThreatFeed (IOC table + ATLAS coverage tabs), VideoScan pages
- Full i18n: English + Albanian

#### Integration Tests
- 9 integration test files: health, auth, scan, admin, denylist, ratelimit, threatfeed, phishing, identity, media
- 52 unit test files across internal packages

#### Documentation
- 54 docs under `docs/` including `docs/INDEX.md`; zero stubs
- 8 security docs: threat model, pentest scope, pre-audit plan, checklist (100%), tabletop runbook
- NIS2/AI Act mapping, NIS3 readiness statement, MITRE ATLAS mapping
- 11 ADRs (ADR-001 through ADR-011)

#### Rust Crates
- `rust/audio-fingerprint`: MFCC pipeline (13 coefficients) + `StreamProcessor` (3-second chunks)
- `rust/triple-hash`: SHA-256 + SHA-512 + Blake3 in one pass
- `rust/c2pa-verify`: C2PA manifest inspection binary with `--certs` PEM chain output

#### Scaffold
- Initial platform scaffold per [ADR-010](../adrs/ADR-010-vertguard-platform-strategy.md)
- CycloneDX 1.4 SBOM (`SBOM.json`), `vertguard.yaml.example`, `ROADMAP.md`
- Ecosystem registration: ECOSYSTEM.md, port 8091, CODEOWNERS

---

## Release roadmap

| Version | Phase | Scope | Target |
|---|---|---|---|
| **v0.1.0** (alpha) | 4.1 | Modules 3 + 4 functional; Module 1 C2PA only. No ML dependencies. | 2026 Q4 |
| **v0.2.0 – v0.4.0** (alpha iterations) | 4.1 | Pattern-engine expansion, ATLAS coverage, operator handbook hardening | 2027 Q1–Q2 |
| **v0.5.0** (beta) | 4.2 | Python ML layer added: Module 1 deepfake detection + Module 2 AI phishing | 2027 Q3 |
| **v0.6.0 – v0.9.0** (beta iterations) | 4.2 | Model zoo expansion, accuracy benchmarking, adversarial robustness | 2027 Q4 – 2028 Q2 |
| **v1.0.0** (stable) | 4.3 | Module 5 complete; real-time video call analysis; NIS3-ready | 2028 Q3 |
| **v1.x** | — | NIS3 consultation feedback; post-quantum C2PA migration path | 2028 Q4 – 2030 |

## Versioning policy

- **Major** bump: breaking API change, data model migration, module
  restructure.
- **Minor** bump: new detection patterns, new MITRE ATLAS entries,
  new endpoints, new model integrations.
- **Patch** bump: bug fixes, pattern refinements that don't change
  behaviour, documentation.

Detection-rule additions are typically **minor** bumps unless they
materially change the false-positive rate in existing deployments —
see [docs/false-positive-handling.md](docs/false-positive-handling.md)
for the threshold rules.
