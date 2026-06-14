import type { AssessmentStatus, ControlStatus, RiskClass } from '../types'

type BadgeStatus = AssessmentStatus | ControlStatus | RiskClass

const styles: Record<string, { bg: string; color: string }> = {
  // Assessment statuses
  draft:         { bg: '#64748b22', color: '#94a3b8' },
  in_progress:   { bg: '#6366f122', color: '#818cf8' },
  under_review:  { bg: '#eab30822', color: '#fcd34d' },
  completed:     { bg: '#22c55e22', color: '#4ade80' },
  archived:      { bg: '#37415122', color: '#6b7280' },

  // Control statuses
  not_assessed:      { bg: '#64748b22', color: '#94a3b8' },
  compliant:         { bg: '#22c55e22', color: '#4ade80' },
  partially_compliant: { bg: '#eab30822', color: '#fcd34d' },
  non_compliant:     { bg: '#ef444422', color: '#f87171' },
  not_applicable:    { bg: '#37415122', color: '#9ca3af' },

  // Risk classes
  INFO:     { bg: '#3b82f622', color: '#60a5fa' },
  WARNING:  { bg: '#eab30822', color: '#fcd34d' },
  CRITICAL: { bg: '#ef444422', color: '#f87171' },
}

const labels: Record<string, string> = {
  not_assessed: 'Not Assessed',
  partially_compliant: 'Partial',
  non_compliant: 'Non-Compliant',
  not_applicable: 'N/A',
  in_progress: 'In Progress',
  under_review: 'Under Review',
}

export function StatusBadge({ status }: { status: BadgeStatus }) {
  const s = styles[status] ?? styles.not_assessed
  const label = labels[status] ?? status.replace(/_/g, ' ')
  return (
    <span
      style={{
        background: s.bg,
        color: s.color,
        border: `1px solid ${s.color}44`,
        borderRadius: 4,
        padding: '2px 8px',
        fontSize: 12,
        fontWeight: 600,
        textTransform: 'uppercase',
        letterSpacing: '0.05em',
        whiteSpace: 'nowrap',
      }}
    >
      {label}
    </span>
  )
}
