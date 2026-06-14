//! VertGuard C2PA verification layer.
//!
//! STATUS: Phase 4.1 scaffold. Wraps `c2pa-rs` (to be added as a
//! dependency during implementation) to verify Content Authenticity
//! Initiative manifests.
//!
//! See `docs/c2pa-integration.md` and
//! `docs/module-1-media-authenticity.md`.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Verification result for a single piece of media.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct VerifyResult {
    pub authentic:    bool,
    pub provenance:   Vec<ProvenanceStep>,
    pub signer:       Option<String>,
    pub certificate:  Option<CertificateInfo>,
    pub error_reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProvenanceStep {
    pub actor:     String,
    pub action:    String,
    pub timestamp: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CertificateInfo {
    pub issuer:   String,
    pub valid_to: String,
}

/// Configuration passed to `verify`.
pub struct VerifyConfig<'a> {
    pub truststore_path:  &'a str,
    pub ocsp_enabled:     bool,
}

/// Verify C2PA provenance on the given content bytes.
///
/// TODO(phase-4.1): wire `c2pa` crate + parse manifest + verify
/// signatures against trust store.
pub fn verify(_content: &[u8], _cfg: &VerifyConfig) -> Result<VerifyResult, VerifyError> {
    Err(VerifyError::NotImplemented)
}

/// Errors from verification.
#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("no C2PA manifest present")]
    NoManifest,

    #[error("signature verification failed: {0}")]
    SignatureInvalid(String),

    #[error("untrusted signer: {0}")]
    UntrustedSigner(String),

    #[error("malformed manifest: {0}")]
    MalformedManifest(String),

    #[error("trust store error: {0}")]
    TrustStore(String),

    #[error("not implemented yet (Phase 4.1 scaffold)")]
    NotImplemented,

    #[error("internal error: {0}")]
    Internal(String),
}
