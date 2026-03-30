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
  - `StartScan`, `GetScan`, `WaitForScan`, `ListScans`
  - `ExportNIS2Evidence` — exports scan result as NIS2Compass-compatible evidence bundle
  - `ExportSARIF` — exports findings as SARIF 2.1.0
- `NIS2CompassClient` — typed client for NIS2Compass v0.1.x API
  - `CreateOrganisation`, `GetOrganisation`, `ListOrganisations`
  - `CreateAssessment`, `GetAssessment`, `ListAssessments`
  - `PatchControl`, `GetControl`
  - `UploadArtifact`, `GetArtifact`
- `citadel.NewClient` — HMAC-signed CITADEL connector client
  - `Evaluate` — submit Kerkese to MARSHAL
  - `EmitWORM` — emit event to WORM log
  - `GetAdvisory` — query AUGUR pre-check advisory
- Typed contracts: `ScanResult`, `Finding`, `IOCBundle`, `IncidentRecord`, `ComplianceAssessment`, `AuditEntry`, `NIS2AuditEntry`
- `webhook` package — signature verification and event router
- Error types: `AuthError`, `NotFoundError`, `RateLimitError`, `ServerError`
- Client options: `WithAPIKey`, `WithTimeout`, `WithHTTPClient`, `WithUserAgent`, `WithRetry`

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
