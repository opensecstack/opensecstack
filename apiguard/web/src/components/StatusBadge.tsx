import type { ScanStatus } from '../types'

const styles: Record<ScanStatus, { bg: string; color: string }> = {
  pending:   { bg: '#64748b22', color: '#94a3b8' },
  running:   { bg: '#6366f122', color: '#818cf8' },
  completed: { bg: '#22c55e22', color: '#4ade80' },
  failed:    { bg: '#ef444422', color: '#f87171' },
  cancelled: { bg: '#64748b22', color: '#94a3b8' },
}

export function StatusBadge({ status }: { status: ScanStatus }) {
  const s = styles[status] ?? styles.pending
  return (
    <span style={{
      background: s.bg, color: s.color,
      border: `1px solid ${s.color}44`,
      borderRadius: 4, padding: '2px 8px',
      fontSize: 12, fontWeight: 600,
      textTransform: 'uppercase', letterSpacing: '0.05em',
    }}>
      {status}
    </span>
  )
}
