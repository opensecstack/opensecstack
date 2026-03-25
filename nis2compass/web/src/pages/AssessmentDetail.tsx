import { useState, useEffect, useCallback } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api'
import type { Assessment, Control, Organisation, AssessmentStatus, ControlStatus } from '../types'
import { StatusBadge } from '../components/StatusBadge'
import './Page.css'

// Valid forward transitions per status
const TRANSITIONS: Partial<Record<AssessmentStatus, { label: string; to: AssessmentStatus }>> = {
  draft:        { label: 'Start Assessment', to: 'in_progress' },
  in_progress:  { label: 'Submit for Review', to: 'under_review' },
  under_review: { label: 'Mark Completed', to: 'completed' },
  completed:    { label: 'Archive', to: 'archived' },
}

const CONTROL_STATUSES: ControlStatus[] = [
  'not_assessed',
  'compliant',
  'partially_compliant',
  'non_compliant',
  'not_applicable',
]

const NIST_COLORS: Record<string, string> = {
  identify: '#6366f1',
  protect:  '#22c55e',
  detect:   '#eab308',
  respond:  '#f97316',
  recover:  '#3b82f6',
}

function NistBadge({ category }: { category: string }) {
  const color = NIST_COLORS[category] ?? '#94a3b8'
  return (
    <span style={{
      background: `${color}22`,
      color,
      border: `1px solid ${color}44`,
      borderRadius: 4,
      padding: '2px 8px',
      fontSize: 11,
      fontWeight: 600,
      textTransform: 'uppercase',
      letterSpacing: '0.05em',
    }}>
      {category}
    </span>
  )
}

// Debounce helper for notes patching
function useDebounce<T>(value: T, delay: number): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delay)
    return () => clearTimeout(t)
  }, [value, delay])
  return debounced
}

interface ControlRowProps {
  control: Control
  onPatch: (measureRef: string, data: Partial<{ status: ControlStatus; notes: string }>) => Promise<void>
}

function ControlRow({ control, onPatch }: ControlRowProps) {
  const [notes, setNotes] = useState(control.notes ?? '')
  const debouncedNotes = useDebounce(notes, 800)
  const [saving, setSaving] = useState(false)

  // Patch notes when debounced value changes (but not on mount)
  const initialNotes = control.notes ?? ''
  useEffect(() => {
    if (debouncedNotes === initialNotes) return
    setSaving(true)
    onPatch(control.measure_ref, { notes: debouncedNotes }).finally(() => setSaving(false))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedNotes])

  async function handleStatusChange(newStatus: ControlStatus) {
    setSaving(true)
    try {
      await onPatch(control.measure_ref, { status: newStatus })
    } finally {
      setSaving(false)
    }
  }

  const evidenceCount = Object.keys(control.evidence ?? {}).length

  return (
    <tr style={{ opacity: saving ? 0.7 : 1 }}>
      <td style={{ fontFamily: 'monospace', color: 'var(--text-muted)', fontSize: 12 }}>
        {control.article_ref}
      </td>
      <td style={{ fontWeight: 500, maxWidth: 220 }}>
        <span title={control.title}>{control.title}</span>
      </td>
      <td><NistBadge category={control.nist_category} /></td>
      <td>
        <select
          className="inline-select"
          value={control.status}
          onChange={e => handleStatusChange(e.target.value as ControlStatus)}
          disabled={saving}
        >
          {CONTROL_STATUSES.map(s => (
            <option key={s} value={s}>
              {s.replace(/_/g, ' ')}
            </option>
          ))}
        </select>
      </td>
      <td style={{ minWidth: 200 }}>
        <input
          className="inline-input"
          value={notes}
          onChange={e => setNotes(e.target.value)}
          placeholder="Add notes..."
          disabled={saving}
        />
      </td>
      <td style={{ textAlign: 'center', color: 'var(--text-muted)' }}>
        {evidenceCount > 0 ? (
          <span style={{ color: '#4ade80', fontWeight: 600 }}>{evidenceCount}</span>
        ) : (
          <span>—</span>
        )}
      </td>
      <td style={{ color: 'var(--text-muted)', fontSize: 12, textAlign: 'right' }}>
        {saving ? 'saving...' : ''}
      </td>
    </tr>
  )
}

export default function AssessmentDetail() {
  const { id } = useParams<{ id: string }>()

  const [assessment, setAssessment] = useState<Assessment | null>(null)
  const [org, setOrg] = useState<Organisation | null>(null)
  const [controls, setControls] = useState<Control[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [transitioning, setTransitioning] = useState(false)
  const [generating, setGenerating] = useState(false)
  const [reportError, setReportError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const asm = await api.assessments.get(id!)
      const ctls = await api.controls.list(id!)
      setAssessment(asm)
      setControls(ctls)
      const orgData = await api.organisations.get(asm.org_id)
      setOrg(orgData)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load assessment')
    } finally {
      setLoading(false)
    }
  }, [id])

  useEffect(() => {
    load()
  }, [load])

  async function handleTransition() {
    if (!assessment) return
    const transition = TRANSITIONS[assessment.status]
    if (!transition) return
    setTransitioning(true)
    try {
      const updated = await api.assessments.patch(assessment.id, { status: transition.to })
      setAssessment(updated)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Status transition failed')
    } finally {
      setTransitioning(false)
    }
  }

  async function handleGenerateReport() {
    if (!assessment) return
    setGenerating(true)
    setReportError(null)
    try {
      const blob = await api.reports.generate(assessment.id)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      const ext = blob.type === 'application/pdf' ? 'pdf' : 'bin'
      a.download = `nis2-assessment-${assessment.id.slice(0, 8)}.${ext}`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (err: unknown) {
      setReportError(err instanceof Error ? err.message : 'Report generation failed')
    } finally {
      setGenerating(false)
    }
  }

  const handlePatchControl = useCallback(
    async (measureRef: string, data: Partial<{ status: ControlStatus; notes: string }>) => {
      const updated = await api.controls.patch(id!, measureRef, data)
      setControls(prev => prev.map(c => (c.measure_ref === measureRef ? updated : c)))
      // Refresh assessment summary after status change
      if (data.status) {
        const updatedAsm = await api.assessments.get(id!)
        setAssessment(updatedAsm)
      }
    },
    [id],
  )

  if (loading) return <p className="loading">Loading assessment...</p>
  if (!assessment) return <p className="error">{error ?? 'Assessment not found'}</p>

  const summary = assessment.summary
  const transition = TRANSITIONS[assessment.status]

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
        {' '}&rsaquo; Assessment
      </div>

      {/* Header */}
      <div className="page-header" style={{ alignItems: 'flex-start', gap: 16, flexWrap: 'wrap' }}>
        <div>
          <h1 className="page-title" style={{ marginBottom: 6 }}>{assessment.title}</h1>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <StatusBadge status={assessment.status} />
            {assessment.assessor && (
              <span className="muted" style={{ fontSize: 13 }}>Assessor: {assessment.assessor}</span>
            )}
            {assessment.due_date && (
              <span className="muted" style={{ fontSize: 13 }}>Due: {assessment.due_date}</span>
            )}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, marginLeft: 'auto', flexWrap: 'wrap' }}>
          {transition && (
            <button
              className="btn-primary"
              onClick={handleTransition}
              disabled={transitioning}
            >
              {transitioning ? 'Updating...' : transition.label}
            </button>
          )}
          <button
            className="btn-secondary"
            onClick={handleGenerateReport}
            disabled={generating}
          >
            {generating ? 'Generating...' : 'Generate Report'}
          </button>
        </div>
      </div>

      {error && <p className="error">{error}</p>}
      {reportError && <p className="error">Report: {reportError}</p>}

      {/* Summary stats */}
      {summary && (
        <div className="stats-grid">
          <div className="stat-card compliant">
            <div className="stat-value" style={{ color: '#4ade80' }}>{summary.compliant}</div>
            <div className="stat-label">Compliant</div>
          </div>
          <div className="stat-card partial">
            <div className="stat-value" style={{ color: '#fcd34d' }}>{summary.partially_compliant}</div>
            <div className="stat-label">Partial</div>
          </div>
          <div className="stat-card non-compliant">
            <div className="stat-value" style={{ color: '#f87171' }}>{summary.non_compliant}</div>
            <div className="stat-label">Non-Compliant</div>
          </div>
          <div className="stat-card not-assessed">
            <div className="stat-value" style={{ color: '#94a3b8' }}>{summary.not_assessed}</div>
            <div className="stat-label">Not Assessed</div>
          </div>
          {summary.overall_risk_score != null && (
            <div className="stat-card">
              <div className="stat-value" style={{ color: '#f97316' }}>
                {summary.overall_risk_score.toFixed(1)}
              </div>
              <div className="stat-label">Risk Score</div>
            </div>
          )}
        </div>
      )}

      {/* Controls table */}
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Ref</th>
              <th>Title</th>
              <th>NIST Category</th>
              <th>Status</th>
              <th>Notes</th>
              <th style={{ textAlign: 'center' }}>Evidence</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {controls.length === 0 ? (
              <tr>
                <td colSpan={7} className="empty">No controls found.</td>
              </tr>
            ) : (
              controls
                .sort((a, b) => a.measure_ref.localeCompare(b.measure_ref))
                .map(control => (
                  <ControlRow
                    key={control.id}
                    control={control}
                    onPatch={handlePatchControl}
                  />
                ))
            )}
          </tbody>
        </table>
      </div>

      {/* Scope / metadata card */}
      {(assessment.scope || assessment.framework_version) && (
        <div className="card" style={{ marginTop: 24 }}>
          <div style={{ display: 'flex', gap: 32, flexWrap: 'wrap' }}>
            {assessment.framework_version && (
              <div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>
                  Framework
                </div>
                <div style={{ fontFamily: 'monospace', fontSize: 13 }}>{assessment.framework_version}</div>
              </div>
            )}
            {assessment.scope && (
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>
                  Scope
                </div>
                <div style={{ fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.6 }}>{assessment.scope}</div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
