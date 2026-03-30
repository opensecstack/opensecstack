# OpenSecStack Rust SDK

Async Rust clients for **APIGuard** (API security scanning) and **NIS2 Compass** (compliance management).

---

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
opensecstack = "0.1"
tokio = { version = "1", features = ["full"] }
```

**MSRV:** Rust 1.75 (stable).

---

## Quick start — APIGuard

```rust
use opensecstack::{APIGuardClient, ScanStatus};
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> opensecstack::Result<()> {
    let client = APIGuardClient::new(
        "https://apiguard.example.com",
        "ak_live_…",
    );

    // Start scan
    let scan = client.create_scan("https://api.example.com/openapi.json").await?;
    println!("Scan started: {}", scan.id);

    // Poll until complete
    let scan_id = scan.id.to_string();
    loop {
        sleep(Duration::from_secs(5)).await;
        let s = client.get_scan(&scan_id).await?;
        match s.status {
            ScanStatus::Completed => {
                println!("Complete! {} findings", s.total_findings);
                break;
            }
            ScanStatus::Failed => {
                eprintln!("Scan failed");
                break;
            }
            _ => {}
        }
    }

    Ok(())
}
```

---

## Quick start — NIS2 Compass

```rust
use opensecstack::{NIS2CompassClient, CreateOrganisationRequest, OrganisationSize};

#[tokio::main]
async fn main() -> opensecstack::Result<()> {
    let client = NIS2CompassClient::new(
        "https://nis2compass.example.com",
        "nk_live_…",
    );

    let org = client.create_organisation(CreateOrganisationRequest {
        name: "Acme Corp".to_string(),
        country: Some("DE".to_string()),
        size: Some(OrganisationSize::Medium),
        ..Default::default()
    }).await?;

    println!("Organisation: {} ({})", org.name, org.id);
    Ok(())
}
```

---

## Authentication

Authentication is **fully automatic**. You provide an API key; the SDK exchanges it for a
short-lived JWT on the first request and caches it transparently.

**SDK-M5 — proactive token refresh:** The SDK parses the `exp` claim from the JWT payload
and refreshes the token at least 60 seconds before expiry, avoiding mid-request failures.

**SDK-M4 — redirect guard:** Both HTTP clients are configured with
`redirect::Policy::none()` to prevent Bearer tokens from leaking to third-party servers
through redirect chains.

You never need to call any auth method manually.

---

## Error handling

All SDK methods return `opensecstack::Result<T>` (an alias for `std::result::Result<T, opensecstack::Error>`).

```rust
use opensecstack::Error;

match client.get_scan("non-existent-id").await {
    Ok(scan) => println!("Got scan: {:?}", scan.status),
    Err(Error::NotFound(path)) => eprintln!("Not found: {path}"),
    Err(Error::RateLimit { retry_after }) => {
        eprintln!("Rate limited, retry after {retry_after}s");
    }
    Err(Error::Auth(msg)) => eprintln!("Auth error: {msg}"),
    Err(Error::Api { status, code, message }) => {
        eprintln!("API error {status} [{code}]: {message}");
    }
    Err(e) => eprintln!("Other error: {e}"),
}
```

### Error variants

| Variant | Cause |
|---------|-------|
| `Error::Api { status, code, message }` | Non-2xx response with structured body |
| `Error::Auth(msg)` | API key exchange failed |
| `Error::RateLimit { retry_after }` | HTTP 429; `retry_after` from `Retry-After` header |
| `Error::NotFound(path)` | HTTP 404 |
| `Error::MaxRetriesExceeded { attempts, last_error }` | All retry attempts exhausted |
| `Error::Transport(e)` | `reqwest` transport-level error |
| `Error::Json(e)` | Serde JSON parse failure |
| `Error::Io(e)` | I/O error (file upload/download) |
| `Error::UnexpectedResponse(msg)` | Unexpected response format |

---

## Builder pattern and custom configuration

Both clients expose a `.builder()` constructor for fine-grained control:

```rust
use opensecstack::APIGuardClient;
use std::time::Duration;

let client = APIGuardClient::builder("https://apiguard.example.com", "ak_live_…")
    .timeout(Duration::from_secs(60))
    .max_retries(3)
    .retry_wait_base(Duration::from_secs(1))
    // Only in test environments — never in production:
    // .danger_accept_invalid_certs(true)
    .build();
```

The same builder API is available on `NIS2CompassClient`.

---

## Streaming reports

For large reports, stream directly to a file instead of buffering in memory:

```rust
use tokio::fs::File;

let mut f = File::create("report.json").await?;
client.get_report_stream(&scan_id, "json", &mut f).await?;
```

The SDK uses a dedicated HTTP client with a 120-second timeout for all report
endpoints, separate from the 30-second default for API calls.

The `get_report_stream` method accepts any type implementing `tokio::io::AsyncWrite + Unpin`,
so you can stream to a file, a network socket, or an in-memory buffer.

---

## APIGuard reference

### `APIGuardClient`

| Method | Description |
|--------|-------------|
| `new(base_url, api_key)` | Create client with defaults |
| `builder(base_url, api_key)` | Create builder |
| `create_scan(spec_url)` | Start scan from spec URL |
| `create_scan_full(opts)` | Start scan with full `CreateScanOptions` |
| `get_scan(scan_id)` | Fetch scan by UUID |
| `list_scans(opts)` | List scans with optional pagination |
| `delete_scan(scan_id)` | Delete a scan |
| `get_findings(scan_id, opts)` | Get findings (handles envelope + plain array) |
| `get_finding(finding_id)` | Get a single finding |
| `patch_finding(finding_id, req)` | Update finding triage status |
| `get_report(scan_id, format)` | Download report into `Bytes` |
| `get_report_stream(scan_id, format, writer)` | Stream report to async writer |
| `upload_spec(file_path)` | Upload OpenAPI spec via multipart |
| `get_audit_log(limit, page)` | Retrieve audit log |

---

## NIS2 Compass reference

### `NIS2CompassClient`

**Organisations**

| Method | Description |
|--------|-------------|
| `create_organisation(req)` | Create organisation |
| `get_organisation(id)` | Get by UUID |
| `list_organisations(page, per_page)` | List with pagination |
| `patch_organisation(id, req)` | Partial update |
| `delete_organisation(id)` | Delete |

**Assessments**

| Method | Description |
|--------|-------------|
| `create_assessment(org_id, req)` | Create assessment for organisation |
| `get_assessment(id)` | Get by UUID |
| `list_assessments(org_id, status)` | List with optional status filter |
| `patch_assessment(id, req)` | Partial update (including status transitions) |
| `delete_assessment(id)` | Delete |

**Controls**

| Method | Description |
|--------|-------------|
| `get_controls(assessment_id)` | All controls for an assessment |
| `get_control(assessment_id, measure_ref)` | Single control by letter ('a'–'j') |
| `patch_control(assessment_id, measure_ref, req)` | Update status, evidence, etc. |

**Artifacts**

| Method | Description |
|--------|-------------|
| `list_artifacts(assessment_id)` | List all artifacts |
| `upload_artifact(assessment_id, file_path, type, control_id, desc)` | Multipart upload |
| `download_artifact(artifact_id, dest_path)` | Download to local file |
| `delete_artifact(artifact_id)` | Delete |

**API Keys**

| Method | Description |
|--------|-------------|
| `list_api_keys()` | List API keys |
| `create_api_key(req)` | Create key (plaintext only on creation) |
| `revoke_api_key(key_id)` | Revoke (delete) |

**Reports and Audit**

| Method | Description |
|--------|-------------|
| `generate_report(assessment_id)` | PDF report as `Bytes` |
| `get_report_stream(assessment_id, format, writer)` | Stream to async writer |
| `get_audit_log(limit, page)` | Paginated audit log |

---

## Async runtime

This SDK requires the [Tokio](https://tokio.rs) async runtime. The `#[tokio::main]`
macro is the simplest way to use it:

```rust
#[tokio::main]
async fn main() -> opensecstack::Result<()> {
    // ...
    Ok(())
}
```

For library consumers, the SDK is compatible with any Tokio runtime (multi-thread or
current-thread). It does **not** block any threads internally.

---

## Feature flags

No optional feature flags are currently exposed. The SDK always uses:

- `rustls-tls` for TLS (no native-tls dependency)
- `reqwest` with JSON and multipart support
- `tokio` with all features

---

## Security notes

- **SDK-M4:** All HTTP clients disable redirect following (`redirect::Policy::none()`).
  This prevents Bearer tokens from being forwarded to unintended hosts through redirects.
- **SDK-M5:** JWT `exp` claims are parsed directly from the token payload.
  The SDK refreshes the token 60 seconds before the server-side expiry, avoiding
  mid-flight 401 errors under token-rotation policies.
- **TLS:** The SDK uses `rustls` and validates TLS certificates by default.
  `danger_accept_invalid_certs(true)` is provided for test environments only.

---

## MSRV policy

Minimum Supported Rust Version: **1.75** (December 2023).

The MSRV is tested in CI and will only be raised with a minor version bump.

---

## Licence

Apache-2.0 — see [LICENSE](../../LICENSE).
