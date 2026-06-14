use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------- enums ----------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrganisationSize {
    Micro,
    Small,
    Medium,
    Large,
    Enterprise,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentStatus {
    Draft,
    InProgress,
    UnderReview,
    Completed,
    Archived,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlStatus {
    Compliant,
    PartiallyCompliant,
    NonCompliant,
    NotApplicable,
    NotAssessed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    Policy,
    Evidence,
    Report,
    Certification,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum APIKeyScope {
    Read,
    ReadWrite,
}

// ---------- organisation ----------

#[derive(Debug, Clone, Deserialize)]
pub struct Organisation {
    pub id: Uuid,
    pub name: String,
    pub industry: Option<String>,
    pub country: Option<String>,
    pub size: Option<OrganisationSize>,
    pub registration_number: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CreateOrganisationRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub industry: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<OrganisationSize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_number: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct PatchOrganisationRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub industry: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<OrganisationSize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_number: Option<String>,
}

// ---------- assessment ----------

#[derive(Debug, Clone, Deserialize)]
pub struct AssessmentStats {
    pub total: u32,
    pub compliant: u32,
    pub partially_compliant: u32,
    pub non_compliant: u32,
    pub not_applicable: u32,
    pub not_assessed: u32,
    pub compliance_pct: f64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Assessment {
    pub id: Uuid,
    pub organisation_id: Uuid,
    pub title: String,
    pub status: AssessmentStatus,
    pub framework_version: Option<String>,
    pub scope: Option<String>,
    pub assessor: Option<String>,
    pub due_date: Option<DateTime<Utc>>,
    pub stats: AssessmentStats,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CreateAssessmentRequest {
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assessor: Option<String>,
    /// ISO 8601 date string, e.g. `"2025-12-31"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub due_date: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct PatchAssessmentRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<AssessmentStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assessor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub due_date: Option<String>,
}

// ---------- control ----------

#[derive(Debug, Clone, Deserialize)]
pub struct Control {
    pub id: Uuid,
    pub assessment_id: Uuid,
    /// Single lowercase letter 'a' through 'j', identifying the NIS2 measure.
    pub measure_ref: char,
    pub title: String,
    pub description: String,
    pub status: ControlStatus,
    pub evidence: Option<serde_json::Value>,
    pub risk_score: Option<f64>,
    pub remediation: Option<String>,
    pub nist_category: Option<String>,
    pub last_reviewed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct PatchControlRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ControlStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<f64>,
}

// ---------- artifact ----------

#[derive(Debug, Clone, Deserialize)]
pub struct Artifact {
    pub id: Uuid,
    pub assessment_id: Uuid,
    pub control_id: Option<Uuid>,
    pub artifact_type: ArtifactType,
    pub filename: String,
    pub mime_type: String,
    pub size_bytes: u64,
    pub file_hash: String,
    pub description: Option<String>,
    pub uploaded_by: Option<String>,
    pub created_at: DateTime<Utc>,
}

// ---------- API keys ----------

#[derive(Debug, Clone, Deserialize)]
pub struct APIKey {
    pub id: Uuid,
    pub label: String,
    pub scope: APIKeyScope,
    pub is_active: bool,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    /// Only present on creation response.
    pub plaintext_key: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateAPIKeyRequest {
    pub label: String,
    pub scope: APIKeyScope,
}

// ---------- audit ----------

#[derive(Debug, Clone, Deserialize)]
pub struct NIS2AuditEntry {
    pub id: Uuid,
    pub actor_id: String,
    pub actor_type: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<Uuid>,
    pub risk_class: String,
    pub object_fingerprint: Option<String>,
    pub ip_address: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub prev_hash: Option<String>,
    pub chain_hash: String,
    pub created_at: DateTime<Utc>,
}

// ---------- health ----------

#[derive(Debug, Clone, Deserialize)]
pub struct HealthStatus {
    pub status: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub db: Option<String>,
    #[serde(default)]
    pub redis: Option<String>,
}
