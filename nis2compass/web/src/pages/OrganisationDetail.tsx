import { useState, useEffect, useCallback, type FormEvent } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api } from '../api'
import type { Assessment, Organisation, Role } from '../types'
import { hasRole } from '../auth'
import { StatusBadge } from '../components/StatusBadge'
import './Page.css'

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
  })
}

export default function OrganisationDetail({ role }: { role: Role }) {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()

  const [org, setOrg] = useState<Organisation | null>(null)
  const [assessments, setAssessments] = useState<Assessment[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Inline edit state
  const [editing, setEditing] = useState(false)
  const [editName, setEditName] = useState('')
  const [editContactEmail, setEditContactEmail] = useState('')
  const [editSaving, setEditSaving] = useState(false)
  const [editError, setEditError] = useState<string | null>(null)

  // New assessment form state
  const [showNewAssessment, setShowNewAssessment] = useState(false)
  const [asmTitle, setAsmTitle] = useState('')
  const [asmAssessor, setAsmAssessor] = useState('')
  const [asmDueDate, setAsmDueDate] = useState('')
  const [asmScope, setAsmScope] = useState('')
  const [asmSubmitting, setAsmSubmitting] = useState(false)
  const [asmFormError, setAsmFormError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [orgData, asmData] = await Promise.all([
        api.organisations.get(id!),
        api.assessments.list(id!),
      ])
      setOrg(orgData)
      setAssessments(asmData)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load organisation')
    } finally {
      setLoading(false)
    }
  }, [id])

  useEffect(() => {
    load()
  }, [load])

  function startEdit() {
    if (!org) return
    setEditName(org.name)
    setEditContactEmail(org.contact_email ?? '')
    setEditError(null)
    setEditing(true)
  }

  async function handleSaveEdit(e: FormEvent) {
    e.preventDefault()
    if (!org || !editName.trim()) return
    setEditSaving(true)
    setEditError(null)
    try {
      const updated = await api.organisations.patch(org.id, {
        name: editName.trim(),
        contact_email: editContactEmail.trim() || undefined,
      })
      setOrg(updated)
      setEditing(false)
    } catch (err: unknown) {
      setEditError(err instanceof Error ? err.message : 'Failed to update organisation')
    } finally {
      setEditSaving(false)
    }
  }

  async function handleCreateAssessment(e: FormEvent) {
    e.preventDefault()
    if (!org || !asmTitle.trim()) return
    setAsmSubmitting(true)
    setAsmFormError(null)
    try {
      const asm = await api.assessments.create(org.id, {
        title: asmTitle.trim(),
        assessor: asmAssessor.trim() || undefined,
        due_date: asmDueDate || undefined,
        scope: asmScope.trim() || undefined,
      })
      setAssessments(prev => [asm, ...prev])
      setShowNewAssessment(false)
      setAsmTitle('')
      setAsmAssessor('')
      setAsmDueDate('')
      setAsmScope('')
      navigate(`/assessments/${asm.id}`)
    } catch (err: unknown) {
      setAsmFormError(err instanceof Error ? err.message : 'Failed to create assessment')
    } finally {
      setAsmSubmitting(false)
    }
  }

  if (loading) return <p className="loading">Loading organisation...</p>
  if (!org) return <p className="error">{error ?? 'Organisation not found'}</p>

  return (
    <div>
      <div className="breadcrumb">
        <Link to="/organisations">Organisations</Link>
        {' '}&rsaquo; {org.name}
      </div>

      {/* Header */}
      <div className="page-header" style={{ alignItems: 'flex-start', flexWrap: 'wrap', gap: 16 }}>
        <div>
          <h1 className="page-title" style={{ marginBottom: 6 }}>{org.name}</h1>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span
              style={{
                background: org.entity_type === 'essential' ? '#6366f122' : '#22c55e22',
                color: org.entity_type === 'essential' ? '#818cf8' : '#4ade80',
                border: `1px solid ${org.entity_type === 'essential' ? '#6366f144' : '#22c55e44'}`,
                borderRadius: 4,
                padding: '2px 8px',
                fontSize: 12,
                fontWeight: 600,
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
              }}
            >
              {org.entity_type}
            </span>
            <span className="muted" style={{ fontSize: 13 }}>{org.industry.replace(/_/g, ' ')}</span>
            <span className="muted" style={{ fontSize: 13 }}>{org.country}</span>
            <span className="muted" style={{ fontSize: 13 }}>{org.size}</span>
            {hasRole(role, 'assessor') && (
              <button
                className="btn-icon"
                onClick={startEdit}
                style={{ marginLeft: 4, padding: '2px 8px', fontSize: 12 }}
              >
                Edit
              </button>
            )}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, marginLeft: 'auto' }}>
          {hasRole(role, 'assessor') && (
            <button
              className="btn-primary"
              onClick={() => setShowNewAssessment(v => !v)}
            >
              {showNewAssessment ? 'Cancel' : '+ New Assessment'}
            </button>
          )}
        </div>
      </div>

      {/* Org metadata card */}
      <div className="card" style={{ marginBottom: 24 }}>
        <div style={{ display: 'flex', gap: 32, flexWrap: 'wrap' }}>
          <div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>
              Created
            </div>
            <div style={{ fontSize: 13 }}>{formatDate(org.created_at)}</div>
          </div>
          <div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>
              Last Updated
            </div>
            <div style={{ fontSize: 13 }}>{formatDate(org.updated_at)}</div>
          </div>
          {org.registration_number && (
            <div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>
                Registration No.
              </div>
              <div style={{ fontSize: 13, fontFamily: 'monospace' }}>{org.registration_number}</div>
            </div>
          )}
          {org.contact_email && (
            <div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>
                Contact Email
              </div>
              <div style={{ fontSize: 13 }}>{org.contact_email}</div>
            </div>
          )}
        </div>
      </div>

      {/* Edit panel */}
      {editing && hasRole(role, 'assessor') && (
        <div className="card form-card" style={{ marginBottom: 24 }}>
          <h3>Edit Organisation</h3>
          {editError && <p className="error">{editError}</p>}
          <form onSubmit={handleSaveEdit}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 24px' }}>
              <div className="form-row">
                <label>Name *</label>
                <input
                  value={editName}
                  onChange={e => setEditName(e.target.value)}
                  placeholder="Acme Energy GmbH"
                  required
                  disabled={editSaving}
                />
              </div>
              <div className="form-row">
                <label>Contact Email</label>
                <input
                  type="email"
                  value={editContactEmail}
                  onChange={e => setEditContactEmail(e.target.value)}
                  placeholder="compliance@example.com"
                  disabled={editSaving}
                />
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="btn-primary" type="submit" disabled={editSaving || !editName.trim()}>
                {editSaving ? 'Saving...' : 'Save Changes'}
              </button>
              <button
                className="btn-secondary"
                type="button"
                onClick={() => setEditing(false)}
                disabled={editSaving}
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      {/* New assessment form */}
      {showNewAssessment && hasRole(role, 'assessor') && (
        <div className="card form-card" style={{ marginBottom: 24 }}>
          <h3>New Assessment</h3>
          {asmFormError && <p className="error">{asmFormError}</p>}
          <form onSubmit={handleCreateAssessment}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 24px' }}>
              <div className="form-row" style={{ gridColumn: '1 / -1' }}>
                <label>Title *</label>
                <input
                  value={asmTitle}
                  onChange={e => setAsmTitle(e.target.value)}
                  placeholder="NIS2 Article 21 Initial Assessment 2026"
                  required
                  disabled={asmSubmitting}
                />
              </div>
              <div className="form-row">
                <label>Assessor</label>
                <input
                  value={asmAssessor}
                  onChange={e => setAsmAssessor(e.target.value)}
                  placeholder="j.smith@example.com"
                  disabled={asmSubmitting}
                />
              </div>
              <div className="form-row">
                <label>Due Date</label>
                <input
                  type="date"
                  value={asmDueDate}
                  onChange={e => setAsmDueDate(e.target.value)}
                  disabled={asmSubmitting}
                />
              </div>
              <div className="form-row" style={{ gridColumn: '1 / -1' }}>
                <label>Scope</label>
                <input
                  value={asmScope}
                  onChange={e => setAsmScope(e.target.value)}
                  placeholder="All NIS and information systems in scope..."
                  disabled={asmSubmitting}
                />
              </div>
            </div>
            <button
              className="btn-primary"
              type="submit"
              disabled={asmSubmitting || !asmTitle.trim()}
            >
              {asmSubmitting ? 'Creating...' : 'Create Assessment'}
            </button>
          </form>
        </div>
      )}

      {error && <p className="error">{error}</p>}

      {/* Assessments list */}
      <div className="section">
        <div className="section-header">
          <h2>Assessments</h2>
        </div>
        {assessments.length === 0 ? (
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
                    <td className="muted">{formatDate(asm.created_at)}</td>
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
    </div>
  )
}
