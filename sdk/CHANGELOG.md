# SDK Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

---

## [Unreleased]

### Added
- IRFlow typed client (Go and Python)
- ThreatFlow typed client (Go and Python)
- Webhook retry helper with exponential backoff

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

**Tools**
- `tds-scanner` — CLI tool for TDS compliance analysis of platform integrations
