//! # OpenSecStack Rust SDK
//!
//! Async Rust clients for the [OpenSecStack](https://github.com/opensecstack/opensecstack)
//! platform, covering both **APIGuard** (API security scanning) and
//! **NIS2 Compass** (compliance management).
//!
//! ## Quick start
//!
//! ```no_run
//! use opensecstack::APIGuardClient;
//!
//! #[tokio::main]
//! async fn main() -> opensecstack::Result<()> {
//!     let client = APIGuardClient::new("https://apiguard.example.com", "ak_live_…");
//!     let scan = client.create_scan("https://api.example.com/openapi.json").await?;
//!     println!("scan {}: {:?}", scan.id, scan.status);
//!     Ok(())
//! }
//! ```
//!
//! ## NIS2 Compass
//!
//! ```no_run
//! use opensecstack::{NIS2CompassClient, CreateOrganisationRequest};
//!
//! #[tokio::main]
//! async fn main() -> opensecstack::Result<()> {
//!     let client = NIS2CompassClient::new("https://nis2compass.example.com", "nk_live_…");
//!     let org = client.create_organisation(CreateOrganisationRequest {
//!         name: "Acme Corp".to_string(),
//!         ..Default::default()
//!     }).await?;
//!     println!("org: {}", org.id);
//!     Ok(())
//! }
//! ```

pub mod apiguard;
pub mod citadel;
pub mod nis2compass;
pub mod webhook;

mod auth;
mod error;

pub use apiguard::APIGuardClient;
pub use error::{Error, Result};
pub use nis2compass::NIS2CompassClient;

// Re-export webhook utilities for convenient top-level access.
pub use webhook::{
    parse_event, verify_signature, WebhookEvent, EVENT_APIGUARD_FINDING_CRITICAL,
    EVENT_APIGUARD_SCAN_COMPLETED, EVENT_APIGUARD_SCAN_FAILED,
    EVENT_CITADEL_HARD_STOP, EVENT_CITADEL_VIGIL_AMBER, EVENT_CITADEL_VIGIL_RED,
    EVENT_NIS2COMPASS_ASSESSMENT_COMPLETED, EVENT_NIS2COMPASS_CONTROL_UPDATED,
};

// Re-export all public APIGuard types for ergonomic use.
pub use apiguard::types::{
    AuditEntry, CreateScanOptions, Finding, FindingSeverity, FindingStatus, GetFindingsOptions,
    ListScansOptions, PatchFindingRequest, RefreshTokenResponse, Scan, ScanStatus,
    UploadSpecResponse,
};

// Re-export CITADEL client and types for ergonomic use.
pub use citadel::CITADELClient;
pub use citadel::types::{GetEventsOptions as CitadelGetEventsOptions, SecurityEvent};

// Re-export all public NIS2 Compass types for ergonomic use.
pub use nis2compass::types::{
    APIKey, APIKeyScope, Artifact, ArtifactType, Assessment, AssessmentStats, AssessmentStatus,
    Control, ControlStatus, CreateAPIKeyRequest, CreateAssessmentRequest,
    CreateOrganisationRequest, NIS2AuditEntry, Organisation, OrganisationSize,
    PatchAssessmentRequest, PatchControlRequest, PatchOrganisationRequest,
};
