// ─── Common ───
export class OpenSecStackError extends Error {
  constructor(
    message: string,
    public readonly statusCode: number,
    public readonly code?: string,
  ) {
    super(message);
    this.name = "OpenSecStackError";
  }
}

export class RateLimitError extends OpenSecStackError {
  constructor(
    message: string,
    public readonly retryAfter: number,
  ) {
    super(message, 429, "RATE_LIMITED");
    this.name = "RateLimitError";
  }
}

// ─── APIGuard Types ───

export type ScanStatus = "pending" | "running" | "completed" | "failed" | "cancelled";
export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";
export type FindingStatus = "open" | "confirmed" | "false_positive" | "accepted" | "fixed";

export interface Scan {
  id: string;
  spec_url: string;
  spec_hash: string;
  target_url: string;
  status: ScanStatus;
  modules: string[];
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  error_message: string;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  owasp_id: string;
  module_id: string;
  title: string;
  description: string;
  remediation: string;
  severity: FindingSeverity;
  cvss_score: number;
  cvss_vector: string;
  endpoint_path: string;
  endpoint_method: string;
  status: FindingStatus;
  triaged_by: string;
  triage_note: string;
  triaged_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface AuditEntry {
  id: string;
  actor_id: string;
  actor_type: string;
  action: string;
  resource_type: string;
  resource_id: string;
  ip_address: string;
  user_agent: string;
  metadata: Record<string, unknown>;
  prev_hash: string | null;
  chain_hash: string;
  created_at: string;
}

export interface UploadSpecResponse {
  spec_path: string;
  spec_hash: string;
  size: number;
}

export interface RefreshTokenResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
}

export interface CreateScanOptions {
  spec_url?: string;
  spec_path?: string;
  target?: string;
  modules?: string[];
  auth_type?: string;
  auth_token?: string;
  auth_header?: string;
}

export interface ListScansOptions {
  page?: number;
  per_page?: number;
}

export interface GetFindingsOptions {
  page?: number;
  per_page?: number;
  status?: FindingStatus;
  severity?: FindingSeverity;
}

export interface ListFindingsOptions {
  page?: number;
  per_page?: number;
  scan_id?: string;
}

export interface PatchFindingRequest {
  status?: string;
  note?: string;
}

// ─── NIS2Compass Types ───

export interface Organisation {
  id: string;
  name: string;
  industry: string;
  country: string;
  size: string;
  entity_type: string;
  registration_number: string;
  contact_email: string;
  created_at: string;
  updated_at: string;
}

export interface CreateOrganisationRequest {
  name: string;
  industry: string;
  country: string;
  size?: string;
  entity_type?: string;
  registration_number?: string;
  contact_email?: string;
}

export interface PatchOrganisationRequest {
  name?: string;
  industry?: string;
  country?: string;
  size?: string;
  entity_type?: string;
  registration_number?: string;
  contact_email?: string;
}

export interface GetOrganisationsOptions {
  page?: number;
  per_page?: number;
}

export interface AssessmentStats {
  total: number;
  by_status: Record<string, number>;
  avg_risk_score: number | null;
}

export interface Assessment {
  id: string;
  org_id: string;
  title: string;
  status: string;
  framework_version: string;
  scope: string;
  assessor: string;
  due_date: string;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
  stats?: AssessmentStats;
}

export interface CreateAssessmentRequest {
  title: string;
  framework_version?: string;
  scope?: string;
  assessor?: string;
  due_date?: string;
}

export interface PatchAssessmentRequest {
  status?: string;
  title?: string;
  scope?: string;
  assessor?: string;
  due_date?: string;
}

export interface GetAssessmentsOptions {
  status?: string;
  page?: number;
  per_page?: number;
}

export interface Control {
  id: string;
  assessment_id: string;
  measure_ref: string;
  article_ref: string;
  title: string;
  description: string;
  nist_category: string;
  status: string;
  evidence: Record<string, unknown> | null;
  risk_score: number | null;
  notes: string;
  gap_description: string;
  remediation_plan: string;
  remediation_due: string;
  remediation_owner: string;
  remediation_status: string;
  external_ticket_url: string;
  remediation_notes: string;
  assessed_by: string;
  assessed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface PatchControlRequest {
  status?: string;
  notes?: string;
  gap_description?: string;
  remediation_plan?: string;
  remediation_due?: string;
  remediation_owner?: string;
  remediation_status?: string;
  external_ticket_url?: string;
  remediation_notes?: string;
  evidence?: Record<string, unknown>;
  risk_score?: number;
}

export interface ListControlsOptions {
  status?: string;
  nist_category?: string;
  measure_ref?: string;
}

export interface Artifact {
  id: string;
  assessment_id: string;
  control_id: string;
  type: string;
  filename: string;
  hash: string;
  size_bytes: number;
  mime_type: string;
  description: string;
  created_by: string;
  created_at: string;
}

export interface APIKey {
  id: string;
  label: string;
  scope: string;
  is_active: boolean;
  created_by: string;
  created_at: string;
  key?: string;
  warning?: string;
}

export interface CreateAPIKeyRequest {
  label: string;
  scope?: string;
}

export interface NIS2AuditEntry {
  id: string;
  action: string;
  actor: string;
  resource_type: string;
  resource_id: string;
  risk_class: string;
  metadata: Record<string, unknown>;
  object_fingerprint: string;
  chain_hash: string;
  prev_hash: string;
  timestamp: string;
}

export interface HealthStatus {
  status: string;
  version?: string;
  db?: string;
  redis?: string;
}

// ─── CITADEL Types ───

export interface SecurityEvent {
  id: string;
  event_type: string;
  source: string;
  actor_id: string;
  actor_type: string;
  resource_type: string;
  resource_id: string;
  severity: string;
  payload: Record<string, unknown>;
  chain_hash: string;
  prev_hash: string | null;
  timestamp: string;
}

export interface GetEventsOptions {
  source?: string;
  event_type?: string;
  since?: string;
  until?: string;
  limit?: number;
  page?: number;
}

// ─── AUGUR Advisory Types ───

export type AdvisoryStatus = "draft" | "published" | "revoked";
export type AdvisorySeverity = "critical" | "high" | "medium" | "low" | "none";

export interface AdvisoryAffects {
  component: string;
  version_min?: string;
  version_max?: string;
}

export interface Advisory {
  id: string;
  title: string;
  description: string;
  severity: AdvisorySeverity;
  status: AdvisoryStatus;
  affects?: AdvisoryAffects[];
  cve?: string;
  references?: string[];
  created_at: string;
  updated_at: string;
}

export interface CreateAdvisoryRequest {
  title: string;
  description: string;
  severity: AdvisorySeverity;
  affects?: AdvisoryAffects[];
  cve?: string;
  references?: string[];
}

export interface PatchAdvisoryRequest {
  title?: string;
  description?: string;
  severity?: AdvisorySeverity;
  status?: AdvisoryStatus;
  affects?: AdvisoryAffects[];
  cve?: string;
  references?: string[];
}

export interface ListAdvisoriesOptions {
  page?: number;
  per_page?: number;
  status?: AdvisoryStatus;
  severity?: AdvisorySeverity;
}

// ─── Paginated Response ───

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  per_page: number;
}
