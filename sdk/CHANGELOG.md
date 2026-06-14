# SDK Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

---

## [Unreleased]

### Added
- IRFlow typed client (Go and Python)
- ThreatFlow typed client (Go and Python)
- Webhook retry helper with exponential backoff
- **`github.com/opensecstack/sdk/password`** — Go sub-module providing the OpenSecStack reference password / API-key hasher. Argon2id (RFC 9106) with an HMAC-SHA256 server-side pepper, PHC string encoding for cross-language portability, constant-time verification, and `NeedsRehash` for parameter rotation. Lives in its own Go module so the core SDK keeps its zero-external-dependency guarantee; apps opt in by importing `github.com/opensecstack/sdk/password` directly. Full test suite covers round-trip, wrong-password, wrong-pepper, malformed input, and PHC format stability
- **`opensecstack-password`** (Python) — sister of `sdk/go/password`. Same Argon2id + HMAC-pepper recipe, same PHC wire format, so hashes produced by either language verify cleanly on the other. Uses `argon2-cffi` for the Argon2id primitive. Published separately from `opensecstack-sdk` so the core SDK keeps its slim dependency footprint. 20 tests cover round-trip, wrong-pepper, malformed PHC, and cross-language format stability
- **IRFlow `auth.Config.Pepper` + `auth.NewHasher(cfg)`** — first adopter wiring. New `IRFLOW_AUTH_PEPPER` config key resolves a shared `*password.Hasher` for any future API-key or user-password feature. Empty pepper is allowed at startup (logs a warning) so adopters can roll out gradually

---

## [1.0.0] — 2026-04-08

Production release of the opensecstack SDK across all four languages.

### Changed
- All platform client references updated from v0.1.x to v1.0.0 API contracts
- Python classifier promoted from `Development Status :: 3 - Alpha` to `Development Status :: 5 - Production/Stable`

### Fixed
- **Python** — `pyproject.toml` now declares `httpx` as a runtime dependency; previously the async clients imported `httpx` but it was missing from `dependencies`, so `pip install opensecstack-sdk` would succeed and then raise `ModuleNotFoundError` on first import. Added `respx` and `pytest-asyncio` to dev extras so the async test suite can be collected
- **Python** — `APIGuardClient._auth_lock` is now a `threading.RLock` instead of `threading.Lock`. The 401-retry path held the lock while calling `_authenticate()`, which in turn tried to re-acquire the same lock and deadlocked. Any concurrent caller that got a 401 would hang their thread indefinitely. `NIS2CompassClient` avoided the bug through a careful call-outside-the-lock pattern and is unchanged

### Stability
- API surface frozen — all public types, methods, and error types are now covered by semantic versioning guarantees
- Breaking changes will only occur in future major versions (2.0.0+)

### Verified
- **Go SDK** — `go test ./...` passes locally on Go 1.26 (12s suite)
- **TypeScript SDK** — `npm test` green, 134 tests across 6 files (vitest, 4.7s)
- **Python SDK** — `pytest` green after dependency fix above
- **Rust SDK** — Rust 1.95 toolchain installed, all dependencies resolved cleanly via `cargo fetch`, source structure verified (8 test files, 6 source modules, 4 examples). Local `cargo build` / `cargo test` on this Windows development box blocked by missing Visual Studio Build Tools (`link.exe`) — not a Rust SDK defect; it's the host environment. GNU-gnu and gnullvm targets were both tried; proc-macro crates must be built for the host which forces MSVC on Windows. The Rust GitHub Actions runners (Linux) have complete toolchains and will verify end-to-end in CI
- **vantage-hash** — TripleHash (BLAKE3 + SHA-256 + SHA-512) crate used by Rust SDK for CITADEL chain verification

---

## [0.1.0] — 2026-03-30

Initial release of the opensecstack SDK.

### Added

**Go SDK** (`sdk/go/opensecstack`)
- `APIGuardClient` — typed client for APIGuard v0.1.x API
  - `CreateScan`, `CreateScanFull`, `GetScan`, `ListScans`, `DeleteScan`
  - `GetFindings`, `GetFinding`, `ListFindings`, `PatchFinding`
  - `GetReport`, `GetReportStream` — JSON, SARIF, HTML, PDF output
  - `UploadSpec`, `GetAuditLog`, `RefreshToken`
- `NIS2CompassClient` — typed client for NIS2 Compass v0.1.x API
  - `CreateOrganisation`, `GetOrganisation`, `GetOrganisations`, `PatchOrganisation`, `DeleteOrganisation`
  - `CreateAssessment`, `GetAssessment`, `GetAssessments`, `PatchAssessment`, `DeleteAssessment`
  - `GetControls`, `ListControls`, `GetControl`, `PatchControl`
  - `ListArtifacts`, `UploadArtifact`, `GetArtifact`, `DownloadArtifact`, `DeleteArtifact`
  - `GenerateReport`, `GetReportStream`, `GetAuditLog`, `GetAuditEntry`
  - `ListAPIKeys`, `CreateAPIKey`, `RevokeAPIKey`
  - `GetHealth`, `GetHealthDetail`
- `NewCITADELClient` — HMAC-SHA256 signed CITADEL connector client
  - `SendEvent` — non-blocking event dispatch via buffered channel + background worker
  - `GetEvents`, `GetEvent` — query the WORM audit chain
  - `VerifyChain` — local SHA-256 chain integrity verification
  - `Drain` — graceful shutdown, waits for in-flight deliveries
- Typed contracts: `Scan`, `Finding`, `Organisation`, `Assessment`, `Control`, `Artifact`, `SecurityEvent`, `AuditEntry`, `NIS2AuditEntry`
- `WebhookRouter` — HMAC-SHA256 signature verification and event routing (`On`, `ServeHTTP`)
- Error types: `AuthError`, `NotFoundError`, `RateLimitError`, `ServerError`

**Python SDK** (`sdk/python/opensecstack`)
- `APIGuardClient` — typed client for APIGuard v0.1.x API
- `NIS2CompassClient` — typed client for NIS2Compass v0.1.x API
- `CITADELClient` — HMAC-signed CITADEL connector client
- Async variants (`opensecstack.aio`) for all clients
- Typed dataclasses matching Go SDK contracts
- `webhook.verify_signature`, `webhook.parse_event`
- Exception types: `AuthError`, `NotFoundError`, `RateLimitError`, `ServerError`

**TypeScript SDK** (`sdk/typescript` — `@opensecstack/sdk`)
- `APIGuardClient` — typed client for APIGuard v0.1.x API
  - `createScan`, `createScanFull`, `getScan`, `listScans`, `deleteScan`
  - `getFindings`, `getFinding`, `listFindings`, `patchFinding`
  - `getReport`, `getReportStream` — ArrayBuffer and ReadableStream output
  - `uploadSpec`, `getAuditLog`, `refreshToken`
- `NIS2CompassClient` — typed client for NIS2 Compass v0.1.x API
  - Full CRUD for organisations, assessments, controls, artifacts, API keys
  - `generateReport`, `getAuditLog`, `getAuditEntry`, `getHealth`, `getHealthDetail`
- `CITADELClient` — HMAC-SHA256 signed CITADEL connector client
  - `sendEvent`, `getEvents`, `getEvent`, `verifyChain`
  - AUGUR advisory methods: `createAdvisory`, `listAdvisories`, `getAdvisory`, `patchAdvisory`, `deleteAdvisory`, `getActiveAdvisories`
- `WebhookRouter` — HMAC-SHA256 signature verification and event routing
  - `verifySignature`, `handle`, `handleHttp` (Node.js HTTP handler)
  - Event type constants matching Go/Python SDKs
- Error types: `OpenSecStackError`, `RateLimitError`, `InvalidSignatureError`
- Built on native `fetch` API (Node.js 18+), no external dependencies

**Tools**
- `tds-scanner` — CLI tool for TDS compliance analysis of platform integrations
