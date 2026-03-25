export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type FindingStatus = 'open' | 'confirmed' | 'false_positive' | 'accepted' | 'fixed'

export interface Scan {
  id: string
  status: ScanStatus
  target: string
  spec_hash?: string
  summary: ScanSummary
  started_at: string
  completed_at?: string
  error?: string
}

export interface ScanSummary {
  total_findings: number
  critical: number
  high: number
  medium: number
  low: number
  info: number
}

export interface Finding {
  id: string
  scan_id: string
  owasp_id: string
  module_id: string
  title: string
  description: string
  severity: Severity
  cvss_score: number
  cvss_vector?: string
  endpoint_path: string
  endpoint_method: string
  evidence: Evidence
  remediation: string
  status: FindingStatus
}

export interface Evidence {
  request: string
  response: string
  detail?: Record<string, unknown>
}
