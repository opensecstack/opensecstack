import type { Severity } from '../types'

const colors: Record<Severity, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  info: '#3b82f6',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span style={{
      background: colors[severity] + '22',
      color: colors[severity],
      border: `1px solid ${colors[severity]}44`,
      borderRadius: 4,
      padding: '2px 8px',
      fontSize: 12,
      fontWeight: 600,
      textTransform: 'uppercase',
      letterSpacing: '0.05em',
    }}>
      {severity}
    </span>
  )
}
