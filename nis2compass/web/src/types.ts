export type OrgSize = 'micro' | 'small' | 'medium' | 'large' | 'enterprise'
export type EntityType = 'essential' | 'important'

export type AssessmentStatus = 'draft' | 'in_progress' | 'under_review' | 'completed' | 'archived'

export type ControlStatus =
  | 'not_assessed'
  | 'compliant'
  | 'partially_compliant'
  | 'non_compliant'
  | 'not_applicable'

export type NistCategory = 'identify' | 'protect' | 'detect' | 'respond' | 'recover'

export type RiskClass = 'INFO' | 'WARNING' | 'CRITICAL'

export interface Organisation {
  id: string
  name: string
  industry: string
  country: string
  size: OrgSize
  entity_type: EntityType
  registration_number?: string | null
  contact_email?: string | null
  created_at: string
  updated_at: string
}

export interface AssessmentSummary {
  total_controls: number
  compliant: number
  partially_compliant: number
  non_compliant: number
  not_assessed: number
  not_applicable: number
  overall_risk_score: number | null
}

export interface Assessment {
  id: string
  org_id: string
  title: string
  status: AssessmentStatus
  framework_version: string
  scope?: string | null
  assessor?: string | null
  due_date?: string | null
  completed_at?: string | null
  created_at: string
  updated_at: string
  summary?: AssessmentSummary
}

export interface Control {
  id: string
  assessment_id: string
  measure_ref: string
  article_ref: string
  title: string
  description?: string | null
  status: ControlStatus
  evidence: Record<string, unknown>
  gap_description?: string | null
  remediation_plan?: string | null
  remediation_due?: string | null
  risk_score?: number | null
  notes?: string | null
  nist_category: NistCategory
  assessed_by?: string | null
  assessed_at?: string | null
  created_at: string
  updated_at: string
  // Remediation panel fields
  remediation_owner?: string | null
  remediation_status?: RemediationStatus | null
  external_ticket_url?: string | null
  remediation_notes?: string | null
}

export type RemediationStatus = 'not_started' | 'in_progress' | 'blocked' | 'completed'

export type ArtifactType =
  | 'policy'
  | 'procedure'
  | 'evidence'
  | 'report'
  | 'screenshot'
  | 'log'
  | 'certificate'
  | 'contract'

export interface Artifact {
  id: string
  assessment_id: string
  control_id?: string | null
  type: ArtifactType
  filename: string
  size_bytes: number
  mime_type: string
  description?: string | null
  created_by: string
  created_at: string
}

export interface ControlTemplate {
  id: number
  measure_ref: string
  article_ref: string
  title: string
  description: string
  nist_category: NistCategory
  guidance?: string | null
}

export interface ApiKey {
  id: string
  label: string
  scope: string
  is_active: boolean
  created_by?: string | null
  created_at: string
  last_used_at?: string | null
  expires_at?: string | null
  key?: string // only present on creation response
}

export interface AuditEntry {
  id: string
  action: string
  actor: string
  resource_type: string
  resource_id?: string | null
  risk_class: RiskClass
  metadata: Record<string, unknown>
  object_fingerprint?: string | null
  prev_hash?: string | null
  chain_hash: string
  timestamp: string
}
