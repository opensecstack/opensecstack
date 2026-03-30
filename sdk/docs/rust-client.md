# SDK Rust Client

The Rust SDK provides async, type-safe clients for APIGuard and NIS2 Compass built on
`tokio` + `reqwest`, with `serde` for JSON, `thiserror` for structured errors, and a
builder pattern for client configuration.

---

## Installation

```toml
[dependencies]
opensecstack = "0.1"
tokio = { version = "1", features = ["full"] }
```

Requires Rust 1.75+ (stable).

---

## APIGuard Client

### Creating a client

```rust
use opensecstack::APIGuardClient;

// Default: 30 s timeout, 2 retries, rustls TLS
let client = APIGuardClient::new(
    "https://apiguard.internal",
    "ak_live_…",
);
```

### Builder for custom settings

```rust
use opensecstack::APIGuardClient;
use std::time::Duration;

let client = APIGuardClient::builder("https://apiguard.internal", "ak_live_…")
    .timeout(Duration::from_secs(60))
    .max_retries(3)
    .retry_wait_base(Duration::from_millis(250))
    .build();
```

### Starting a scan

```rust
use opensecstack::CreateScanOptions;

// Convenience: scan from spec URL
let scan = client.create_scan("https://api.example.com/openapi.json").await?;
println!("Scan ID: {}", scan.id);

// Full options
let scan = client.create_scan_full(CreateScanOptions {
    target_url: "https://api.example.com".to_string(),
    spec_url: Some("https://api.example.com/openapi.json".to_string()),
    modules: vec!["bola".to_string(), "broken_auth".to_string(), "injection".to_string()],
    auth_type: Some("bearer".to_string()),
    auth_token: Some("eyJhb…".to_string()),
    ..Default::default()
}).await?;
```

### Polling for results

```rust
use opensecstack::ScanStatus;
use tokio::time::{sleep, Duration};

let scan_id = scan.id.to_string();
let completed = loop {
    sleep(Duration::from_secs(5)).await;
    let s = client.get_scan(&scan_id).await?;
    match s.status {
        ScanStatus::Completed | ScanStatus::Failed | ScanStatus::Cancelled => break s,
        _ => {}
    }
};
println!("{} findings", completed.total_findings);
```

### Listing scans

```rust
use opensecstack::ListScansOptions;

let scans = client.list_scans(Some(ListScansOptions {
    page: Some(1),
    per_page: Some(20),
    status: None,
})).await?;
```

### Getting findings

```rust
use opensecstack::{GetFindingsOptions, FindingSeverity};

let findings = client.get_findings(&scan_id, Some(GetFindingsOptions {
    severity: Some(FindingSeverity::Critical),
    ..Default::default()
})).await?;

for f in &findings {
    println!("[{}] {} {} — {}", f.owasp_id, f.endpoint_method, f.endpoint_path, f.title);
}
```

The SDK transparently handles both `{"data": [...]}` envelope and plain-array response
formats for the findings endpoint.

### Triaging a finding

```rust
use opensecstack::{PatchFindingRequest, FindingStatus};

let updated = client.patch_finding(
    &finding_id,
    PatchFindingRequest {
        status: FindingStatus::FalsePositive,
        note: Some("Confirmed safe after manual review.".to_string()),
    },
).await?;
```

### Downloading a report

```rust
// Into memory (for small reports)
let bytes = client.get_report(&scan_id, "json").await?;

// Streamed (for large reports)
use tokio::fs::File;
let mut f = File::create("report.json").await?;
client.get_report_stream(&scan_id, "json", &mut f).await?;
```

Supported format strings: `"json"`, `"pdf"`, `"sarif"` (server-dependent).

### Uploading a spec file

```rust
let resp = client.upload_spec("/path/to/openapi.yaml").await?;
println!("Uploaded: {} (hash: {})", resp.spec_path, resp.spec_hash);
```

### Audit log

```rust
let entries = client.get_audit_log(50, 1).await?;
for e in &entries {
    println!("{} — {} by {}", e.created_at, e.action, e.actor_id);
}
```

---

## NIS2 Compass Client

### Creating a client

```rust
use opensecstack::NIS2CompassClient;

let client = NIS2CompassClient::new(
    "https://nis2compass.internal",
    "nk_live_…",
);
```

### Organisations

```rust
use opensecstack::{CreateOrganisationRequest, OrganisationSize, PatchOrganisationRequest};

// Create
let org = client.create_organisation(CreateOrganisationRequest {
    name: "Example GmbH".to_string(),
    industry: Some("financial_services".to_string()),
    country: Some("DE".to_string()),
    size: Some(OrganisationSize::Medium),
    registration_number: Some("HRB 123456 B".to_string()),
}).await?;

// Get
let org = client.get_organisation(&org.id.to_string()).await?;

// List
let orgs = client.list_organisations(Some(1), Some(20)).await?;

// Update
let updated = client.patch_organisation(
    &org.id.to_string(),
    PatchOrganisationRequest {
        name: Some("Example GmbH (Renamed)".to_string()),
        ..Default::default()
    },
).await?;

// Delete
client.delete_organisation(&org.id.to_string()).await?;
```

### Assessments

```rust
use opensecstack::{
    CreateAssessmentRequest, PatchAssessmentRequest, AssessmentStatus
};

// Create
let assessment = client.create_assessment(
    &org.id.to_string(),
    CreateAssessmentRequest {
        title: "NIS2 Annual Assessment 2024".to_string(),
        scope: Some("All production systems".to_string()),
        assessor: Some("ciso@example.de".to_string()),
        due_date: Some("2024-12-31".to_string()),
    },
).await?;

// Update status
let updated = client.patch_assessment(
    &assessment.id.to_string(),
    PatchAssessmentRequest {
        status: Some(AssessmentStatus::InProgress),
        ..Default::default()
    },
).await?;
println!("Compliance: {:.1}%", updated.stats.compliance_pct);

// List with filter
let drafts = client.list_assessments(
    &org.id.to_string(),
    Some(AssessmentStatus::Draft),
).await?;
```

### Controls

NIS2 Article 21 defines 10 security measures, referenced by letters 'a' through 'j'.

```rust
use opensecstack::{PatchControlRequest, ControlStatus};

// All controls for an assessment
let controls = client.get_controls(&assessment.id.to_string()).await?;

// Single control
let control_a = client.get_control(&assessment.id.to_string(), 'a').await?;
println!("Measure (a): {} — {:?}", control_a.title, control_a.status);

// Update control
let updated = client.patch_control(
    &assessment.id.to_string(),
    'a',
    PatchControlRequest {
        status: Some(ControlStatus::Compliant),
        evidence: Some(serde_json::json!({
            "document_ref": "IS-POL-001",
            "approved_by": "CISO",
            "approved_at": "2024-01-15"
        })),
        remediation: None,
        risk_score: Some(2.5),
    },
).await?;
```

### Artifacts

```rust
use opensecstack::ArtifactType;

// Upload
let artifact = client.upload_artifact(
    &assessment.id.to_string(),
    "/path/to/security_policy.pdf",
    ArtifactType::Policy,
    Some(&control_a.id.to_string()), // optional: tie to a control
    Some("Information Security Policy v3.0"),
).await?;
println!("Artifact: {} ({} bytes)", artifact.filename, artifact.size_bytes);

// List
let artifacts = client.list_artifacts(&assessment.id.to_string()).await?;

// Download
client.download_artifact(&artifact.id.to_string(), "/tmp/policy_download.pdf").await?;

// Delete
client.delete_artifact(&artifact.id.to_string()).await?;
```

### API keys

```rust
use opensecstack::{CreateAPIKeyRequest, APIKeyScope};

// List
let keys = client.list_api_keys().await?;

// Create — plaintext_key is ONLY present at creation time
let key = client.create_api_key(CreateAPIKeyRequest {
    label: "CI Pipeline Key".to_string(),
    scope: APIKeyScope::Read,
}).await?;
println!("Key (save this now!): {}", key.plaintext_key.unwrap());

// Revoke
client.revoke_api_key(&key.id.to_string()).await?;
```

### Reports

```rust
// PDF into memory
let pdf_bytes = client.generate_report(&assessment.id.to_string()).await?;
std::fs::write("report.pdf", &pdf_bytes)?;

// Streamed (recommended for large files)
use tokio::fs::File;
let mut f = File::create("report.pdf").await?;
client.get_report_stream(&assessment.id.to_string(), "pdf", &mut f).await?;
```

### NIS2 Audit log

The audit log entries include a tamper-evident hash chain (`prev_hash` / `chain_hash`):

```rust
let entries = client.get_audit_log(100, 1).await?;
for entry in &entries {
    println!(
        "{} {} {} (risk: {})",
        entry.created_at, entry.actor_id, entry.action, entry.risk_class
    );
    if let Some(ref prev) = entry.prev_hash {
        println!("  prev_hash: {}", &prev[..16]);
    }
    println!("  chain_hash: {}", &entry.chain_hash[..16]);
}
```

---

## Error handling

```rust
use opensecstack::Error;

match result {
    Err(Error::NotFound(path))           => { /* 404 */ }
    Err(Error::RateLimit { retry_after }) => { /* 429, back off */ }
    Err(Error::Auth(msg))                => { /* bad API key */ }
    Err(Error::Api { status, code, .. }) => { /* structured API error */ }
    Err(Error::Transport(e))             => { /* network failure */ }
    Err(Error::Json(e))                  => { /* parse failure */ }
    Err(Error::Io(e))                    => { /* file I/O failure */ }
    _ => {}
}
```

---

## Shared types

| Type | Module | Description |
|------|--------|-------------|
| `Scan` | `apiguard` | Scan record |
| `Finding` | `apiguard` | Security finding |
| `ScanStatus` | `apiguard` | `Pending \| Running \| Completed \| Failed \| Cancelled` |
| `FindingSeverity` | `apiguard` | `Critical \| High \| Medium \| Low \| Info` |
| `FindingStatus` | `apiguard` | `Open \| Confirmed \| FalsePositive \| Accepted \| Fixed` |
| `AuditEntry` | `apiguard` | APIGuard audit log entry |
| `Organisation` | `nis2compass` | Organisation record |
| `Assessment` | `nis2compass` | NIS2 assessment |
| `AssessmentStats` | `nis2compass` | Compliance statistics |
| `Control` | `nis2compass` | NIS2 Article 21 measure (a–j) |
| `Artifact` | `nis2compass` | Uploaded evidence or policy document |
| `APIKey` | `nis2compass` | API key record |
| `NIS2AuditEntry` | `nis2compass` | NIS2 Compass audit log entry with hash chain |
| `OrganisationSize` | `nis2compass` | `Micro \| Small \| Medium \| Large \| Enterprise` |
| `AssessmentStatus` | `nis2compass` | `Draft \| InProgress \| UnderReview \| Completed \| Archived` |
| `ControlStatus` | `nis2compass` | `Compliant \| PartiallyCompliant \| NonCompliant \| NotApplicable \| NotAssessed` |
| `ArtifactType` | `nis2compass` | `Policy \| Evidence \| Report \| Certification \| Other` |

All types are re-exported from the crate root for ergonomic use:

```rust
use opensecstack::{Scan, Finding, Assessment, Control, /* etc. */};
```

---

## Security

- **SDK-M4:** HTTP redirect following is disabled on all clients to prevent Bearer tokens
  from leaking to redirect targets.
- **SDK-M5:** JWT `exp` is parsed from the token payload; the SDK refreshes tokens
  60 seconds before expiry to prevent mid-flight failures.
- **TLS:** Uses `rustls` exclusively; native-tls is not a dependency.
- **No secrets in logs:** The SDK never logs API keys or access tokens (tracing calls
  only include method, path, and status codes at DEBUG level).

---

## Examples

Run the bundled examples:

```bash
# APIGuard full scan workflow
APIGUARD_URL=https://... APIGUARD_API_KEY=ak_live_... SPEC_URL=https://... \
  cargo run --example scan_and_report

# NIS2 Compass full assessment workflow
NIS2_URL=https://... NIS2_API_KEY=nk_live_... \
  cargo run --example nis2_assessment
```

---

## Testing

```bash
cd sdk/rust
cargo test --all-features
```

Integration tests use [wiremock](https://crates.io/crates/wiremock) — no running
server required.
