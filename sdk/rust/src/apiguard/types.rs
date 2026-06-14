use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------- enums ----------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Open,
    Confirmed,
    FalsePositive,
    Accepted,
    Fixed,
}

// ---------- core types ----------

#[derive(Debug, Clone, Deserialize)]
pub struct Scan {
    pub id: Uuid,
    pub target_url: String,
    pub spec_url: Option<String>,
    pub spec_hash: Option<String>,
    pub status: ScanStatus,
    pub modules: Vec<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub total_findings: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub info_count: i32,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub scan_id: Uuid,
    pub owasp_id: String,
    pub module_id: String,
    pub title: String,
    pub description: String,
    pub severity: FindingSeverity,
    pub cvss_score: f64,
    pub cvss_vector: Option<String>,
    pub endpoint_path: String,
    pub endpoint_method: String,
    pub evidence_request: Option<String>,
    pub evidence_response: Option<String>,
    pub remediation: Option<String>,
    pub status: FindingStatus,
    pub triaged_by: Option<String>,
    pub triaged_at: Option<DateTime<Utc>>,
    pub triage_note: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditEntry {
    pub id: Uuid,
    pub actor_id: String,
    pub actor_type: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<Uuid>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub prev_hash: Option<String>,
    pub chain_hash: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UploadSpecResponse {
    pub spec_path: String,
    pub spec_hash: String,
    pub size: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RefreshTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

// ---------- request types ----------

#[derive(Debug, Clone, Default, Serialize)]
pub struct CreateScanOptions {
    pub target_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec_hash: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub modules: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct PatchFindingRequest {
    pub status: FindingStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct GetFindingsOptions {
    pub severity: Option<FindingSeverity>,
    pub status: Option<FindingStatus>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct ListScansOptions {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub status: Option<ScanStatus>,
}

impl Default for FindingStatus {
    fn default() -> Self {
        FindingStatus::Open
    }
}
