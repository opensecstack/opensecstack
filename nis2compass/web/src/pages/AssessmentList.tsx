import { useState, useEffect, useCallback, type FormEvent } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api'
import type { Assessment, Organisation } from '../types'
import { StatusBadge } from '../components/StatusBadge'
import './Page.css'

export default function AssessmentList() {
  const { orgId } = useParams<{ orgId: string }>()

  const [org, setOrg] = useState<Organisation | null>(null)
  const [assessments, setAssessments] = useState<Assessment[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showForm, setShowForm] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  const [title, setTitle] = useState('')
  const [assessor, setAssessor] = useState('')
  const [dueDate, setDueDate] = useState('')
  const [scope, setScope] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [orgData, asmData] = await Promise.all([
        api.organisations.get(orgId!),
        api.assessments.list(orgId!),
      ])
      setOrg(orgData)
      setAssessments(asmData)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load')
    } finally {
      setLoading(false)
    }
  }, [orgId])

  useEffect(() => {
    if (orgId) load()
  }, [orgId, load])

  async function handleCreate(e: FormEvent) {
    e.preventDefault()
    if (!title.trim()) return
    setSubmitting(true)
    setFormError(null)
    try {
      const asm = await api.assessments.create(orgId!, {
        title: title.trim(),
        assessor: assessor.trim() || undefined,
        due_date: dueDate || undefined,
        scope: scope.trim() || undefined,
      })
      setAssessments(prev => [asm, ...prev])
      setShowForm(false)
      setTitle('')
      setAssessor('')
      setDueDate('')
      setScope('')
    } catch (err: unknown) {
      setFormError(err instanceof Error ? err.message : 'Failed to create assessment')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div>
      <div className="breadcrumb">
        <Link to="/organisations">Organisations</Link>
        {org && <> &rsaquo; {org.name}</>}
      </div>

      <div className="page-header">
        <h1 className="page-title">Assessments{org ? ` — ${org.name}` : ''}</h1>
        <button className="btn-primary" onClick={() => setShowForm(v => !v)}>
          {showForm ? 'Cancel' : '+ New Assessment'}
        </button>
      </div>

      {showForm && (
        <div className="card form-card" style={{ marginBottom: 24 }}>
          <h3>New Assessment</h3>
          {formError && <p className="error">{formError}</p>}
          <form onSubmit={handleCreate}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 24px' }}>
              <div className="form-row" style={{ gridColumn: '1 / -1' }}>
                <label>Title *</label>
                <input
                  value={title}
                  onChange={e => setTitle(e.target.value)}
                  placeholder="NIS2 Article 21 Initial Assessment 2026"
                  required
                  disabled={submitting}
                />
              </div>
              <div className="form-row">
                <label>Assessor</label>
                <input
                  value={assessor}
                  onChange={e => setAssessor(e.target.value)}
                  placeholder="j.smith@example.com"
                  disabled={submitting}
                />
              </div>
              <div className="form-row">
                <label>Due Date</label>
                <input
                  type="date"
                  value={dueDate}
                  onChange={e => setDueDate(e.target.value)}
                  disabled={submitting}
                />
              </div>
              <div className="form-row" style={{ gridColumn: '1 / -1' }}>
                <label>Scope</label>
                <input
                  value={scope}
                  onChange={e => setScope(e.target.value)}
                  placeholder="All NIS and information systems in scope..."
                  disabled={submitting}
                />
              </div>
            </div>
            <button className="btn-primary" type="submit" disabled={submitting || !title.trim()}>
              {submitting ? 'Creating...' : 'Create Assessment'}
            </button>
          </form>
        </div>
      )}

      {error && <p className="error">{error}</p>}
      {loading ? (
        <p className="loading">Loading assessments...</p>
      ) : assessments.length === 0 ? (
        <p className="empty">No assessments yet. Create one to begin the compliance workflow.</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Title</th>
                <th>Status</th>
                <th>Assessor</th>
                <th>Due Date</th>
                <th>Created</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {assessments.map(asm => (
                <tr key={asm.id}>
                  <td style={{ fontWeight: 500 }}>{asm.title}</td>
                  <td><StatusBadge status={asm.status} /></td>
                  <td className="muted">{asm.assessor ?? '—'}</td>
                  <td className="muted">{asm.due_date ?? '—'}</td>
                  <td className="muted">{new Date(asm.created_at).toLocaleDateString()}</td>
                  <td>
                    <Link
                      to={`/assessments/${asm.id}`}
                      className="btn-primary"
                      style={{ padding: '4px 12px', fontSize: 13 }}
                    >
                      Open
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
