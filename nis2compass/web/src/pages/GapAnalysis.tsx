import { useState, useEffect, useCallback } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, compliance } from '../api'
import type { Assessment, Organisation, Role } from '../types'
import { hasRole } from '../auth'
import './Page.css'

// ---------------------------------------------------------------------------
// Types (the API returns untyped `any` for gaps; define locally)
// ---------------------------------------------------------------------------

interface Gap {
  id?: string
  measure_ref: string
  gap_description: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  recommendation?: string | null
  [key: string]: unknown
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SEVERITY_STYLES: Record<string, { bg: string; color: string }> = {
  low:      { bg: '#22c55e22', color: '#4ade80' },
  medium:   { bg: '#eab30822', color: '#fcd34d' },
  high:     { bg: '#f9731622', color: '#fb923c' },
  critical: { bg: '#ef444422', color: '#f87171' },
}

function SeverityBadge({ severity }: { severity: string }) {
  const s = SEVERITY_STYLES[severity.toLowerCase()] ?? SEVERITY_STYLES.medium
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
      {severity}
    </span>
  )
}

// ---------------------------------------------------------------------------
// GapAnalysis page
// ---------------------------------------------------------------------------

export default function GapAnalysis({ role }: { role: Role }) {
  const { id } = useParams<{ id: string }>()

  const [assessment, setAssessment] = useState<Assessment | null>(null)
  const [org, setOrg] = useState<Organisation | null>(null)
  const [gaps, setGaps] = useState<Gap[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [analyzeError, setAnalyzeError] = useState<string | null>(null)

  const loadGaps = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [asm, gapData] = await Promise.all([
        api.assessments.get(id!),
        compliance.getGaps(id!),
      ])
      setAssessment(asm)
      const orgData = await api.organisations.get(asm.org_id)
      setOrg(orgData)
      setGaps((gapData.gaps ?? []) as unknown as Gap[])
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load gap analysis')
    } finally {
      setLoading(false)
    }
  }, [id])

  useEffect(() => {
    loadGaps()
  }, [loadGaps])

  async function handleAnalyze() {
    setAnalyzing(true)
    setAnalyzeError(null)
    try {
      await compliance.analyzeGaps(id!)
      await loadGaps()
    } catch (err: unknown) {
      setAnalyzeError(err instanceof Error ? err.message : 'Gap analysis failed')
    } finally {
      setAnalyzing(false)
    }
  }

  // Group gaps by measure_ref
  const grouped = gaps.reduce<Record<string, Gap[]>>((acc, gap) => {
    const key = gap.measure_ref ?? 'unknown'
    if (!acc[key]) acc[key] = []
    acc[key].push(gap)
    return acc
  }, {})

  // Summary counts by severity
  const severityCounts = gaps.reduce<Record<string, number>>((acc, gap) => {
    const sev = (gap.severity ?? 'unknown').toLowerCase()
    acc[sev] = (acc[sev] ?? 0) + 1
    return acc
  }, {})

  if (loading) return <p className="loading">Loading gap analysis...</p>
  if (!assessment) return <p className="error">{error ?? 'Assessment not found'}</p>

  return (
    <div>
      <div className="breadcrumb">
        <Link to="/organisations">Organisations</Link>
        {org && (
          <>
            {' '}&rsaquo;{' '}
            <Link to={`/organisations/${org.id}/assessments`}>{org.name}</Link>
          </>
        )}
        {' '}&rsaquo;{' '}
        <Link to={`/assessments/${id}`}>{assessment.title}</Link>
        {' '}&rsaquo; Gap Analysis
      </div>

      {/* Header */}
      <div className="page-header" style={{ alignItems: 'flex-start', flexWrap: 'wrap', gap: 16 }}>
        <div>
          <h1 className="page-title" style={{ marginBottom: 6 }}>Gap Analysis</h1>
          <p className="muted" style={{ fontSize: 13, margin: 0 }}>{assessment.title}</p>
        </div>
        <div style={{ display: 'flex', gap: 8, marginLeft: 'auto' }}>
          {hasRole(role, 'assessor') && (
            <button
              className="btn-primary"
              onClick={handleAnalyze}
              disabled={analyzing}
            >
              {analyzing ? 'Analysing...' : 'Run Gap Analysis'}
            </button>
          )}
          <Link
            to={`/assessments/${id}`}
            className="btn-secondary"
            style={{ display: 'inline-flex', alignItems: 'center' }}
          >
            Back to Assessment
          </Link>
        </div>
      </div>

      {error && <p className="error">{error}</p>}
      {analyzeError && <p className="error">Analysis error: {analyzeError}</p>}

      {/* Summary stats */}
      {gaps.length > 0 && (
        <div className="stats-grid" style={{ marginBottom: 32 }}>
          <div className="stat-card">
            <div className="stat-value" style={{ color: 'var(--text)' }}>{gaps.length}</div>
            <div className="stat-label">Total Gaps</div>
          </div>
          {(['critical', 'high', 'medium', 'low'] as const).map(sev => {
            const count = severityCounts[sev] ?? 0
            if (count === 0) return null
            const s = SEVERITY_STYLES[sev]
            return (
              <div key={sev} className="stat-card" style={{ borderColor: `${s.color}44` }}>
                <div className="stat-value" style={{ color: s.color }}>{count}</div>
                <div className="stat-label">{sev.charAt(0).toUpperCase() + sev.slice(1)}</div>
              </div>
            )
          })}
        </div>
      )}

      {/* Gaps grouped by measure ref */}
      {gaps.length === 0 ? (
        <p className="empty">
          No gaps recorded. Run the analysis to identify compliance gaps for this assessment.
        </p>
      ) : (
        Object.entries(grouped)
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([measureRef, measureGaps]) => (
            <div key={measureRef} className="card" style={{ marginBottom: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
                <span
                  style={{
                    fontFamily: 'monospace',
                    fontSize: 13,
                    color: 'var(--text-muted)',
                    background: 'var(--surface2)',
                    border: '1px solid var(--border)',
                    borderRadius: 4,
                    padding: '2px 8px',
                  }}
                >
                  {measureRef}
                </span>
                <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>
                  {measureGaps.length} gap{measureGaps.length !== 1 ? 's' : ''}
                </span>
              </div>

              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Severity</th>
                      <th>Gap Description</th>
                      <th>Recommendation</th>
                    </tr>
                  </thead>
                  <tbody>
                    {measureGaps.map((gap, idx) => (
                      <tr key={gap.id ?? idx}>
                        <td style={{ whiteSpace: 'nowrap' }}>
                          <SeverityBadge severity={gap.severity ?? 'unknown'} />
                        </td>
                        <td style={{ fontSize: 13, lineHeight: 1.5 }}>
                          {gap.gap_description ?? '—'}
                        </td>
                        <td style={{ fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.5 }}>
                          {gap.recommendation ?? '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ))
      )}
    </div>
  )
}
