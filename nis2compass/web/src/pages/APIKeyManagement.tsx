import { useState, useEffect, type FormEvent } from 'react'
import { api } from '../api'
import type { ApiKey } from '../types'
import './Page.css'

export default function APIKeyManagement() {
  const [keys, setKeys] = useState<ApiKey[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showForm, setShowForm] = useState(false)
  const [label, setLabel] = useState('')
  const [scope, setScope] = useState('read_write')
  const [submitting, setSubmitting] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)
  const [createdKey, setCreatedKey] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [revoking, setRevoking] = useState<string | null>(null)

  useEffect(() => { load() }, [])

  async function load() {
    setLoading(true)
    setError(null)
    try {
      setKeys(await api.apiKeys.list())
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load API keys')
    } finally {
      setLoading(false)
    }
  }

  async function handleCreate(e: FormEvent) {
    e.preventDefault()
    if (!label.trim()) return
    setSubmitting(true)
    setFormError(null)
    setCreatedKey(null)
    try {
      const key = await api.apiKeys.create({ label: label.trim(), scope })
      if (key.key) setCreatedKey(key.key)
      setKeys(prev => [key, ...prev])
      setShowForm(false)
      setLabel('')
      setScope('read_write')
    } catch (err: unknown) {
      setFormError(err instanceof Error ? err.message : 'Failed to create API key')
    } finally {
      setSubmitting(false)
    }
  }

  async function handleRevoke(id: string) {
    if (!window.confirm('Revoke this API key? This cannot be undone.')) return
    setRevoking(id)
    try {
      await api.apiKeys.revoke(id)
      setKeys(prev => prev.filter(k => k.id !== id))
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to revoke')
    } finally {
      setRevoking(null)
    }
  }

  async function handleCopy() {
    if (!createdKey) return
    try {
      await navigator.clipboard.writeText(createdKey)
    } catch {
      const el = document.createElement('textarea')
      el.value = createdKey
      document.body.appendChild(el)
      el.select()
      document.execCommand('copy')
      document.body.removeChild(el)
    }
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">API Keys</h1>
        <button className="btn-primary" onClick={() => { setShowForm(v => !v); setCreatedKey(null) }}>
          {showForm ? 'Cancel' : '+ New API Key'}
        </button>
      </div>

      {createdKey && (
        <div className="card" style={{ background: '#22c55e12', borderColor: '#22c55e44', marginBottom: 16 }}>
          <div style={{ fontSize: 13, color: '#4ade80', fontWeight: 600, marginBottom: 8 }}>
            API key created — copy it now, it will not be shown again
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <code style={{ background: 'var(--surface2)', padding: '6px 12px', borderRadius: 4, fontSize: 13, flex: 1, wordBreak: 'break-all' }}>
              {createdKey}
            </code>
            <button className="btn-primary" onClick={handleCopy} style={{ whiteSpace: 'nowrap' }}>
              {copied ? 'Copied!' : 'Copy'}
            </button>
          </div>
        </div>
      )}

      {showForm && (
        <div className="card form-card" style={{ marginBottom: 24 }}>
          <h3>New API Key</h3>
          {formError && <p className="error">{formError}</p>}
          <form onSubmit={handleCreate}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 24px' }}>
              <div className="form-row">
                <label>Label *</label>
                <input value={label} onChange={e => setLabel(e.target.value)} placeholder="e.g. CI/CD Pipeline" required disabled={submitting} />
              </div>
              <div className="form-row">
                <label>Scope *</label>
                <select value={scope} onChange={e => setScope(e.target.value)} disabled={submitting}>
                  <option value="read_write">Read + Write</option>
                  <option value="read">Read Only</option>
                </select>
              </div>
            </div>
            <button className="btn-primary" type="submit" disabled={submitting || !label.trim()}>
              {submitting ? 'Creating...' : 'Create API Key'}
            </button>
          </form>
        </div>
      )}

      {error && <p className="error">{error}</p>}
      {loading ? (
        <p className="loading">Loading API keys...</p>
      ) : keys.length === 0 ? (
        <p className="empty">No API keys. Create one to authenticate with the API.</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Label</th>
                <th>Scope</th>
                <th>Status</th>
                <th>Created</th>
                <th>Last Used</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {keys.map(k => (
                <tr key={k.id} style={{ opacity: revoking === k.id ? 0.5 : 1 }}>
                  <td style={{ fontWeight: 500 }}>{k.label || '(unlabeled)'}</td>
                  <td>
                    <span className="artifact-type-badge" style={k.scope === 'read' ? { background: '#64748b22', color: '#94a3b8', borderColor: '#64748b44' } : {}}>
                      {k.scope}
                    </span>
                  </td>
                  <td>
                    <span style={{
                      display: 'inline-block', borderRadius: 4, padding: '2px 8px', fontSize: 11, fontWeight: 600, textTransform: 'uppercase' as const,
                      background: k.is_active ? '#22c55e22' : '#ef444422',
                      color: k.is_active ? '#4ade80' : '#f87171',
                      border: `1px solid ${k.is_active ? '#22c55e44' : '#ef444444'}`,
                    }}>
                      {k.is_active ? 'Active' : 'Revoked'}
                    </span>
                  </td>
                  <td className="muted">{new Date(k.created_at).toLocaleDateString()}</td>
                  <td className="muted">{k.last_used_at ? new Date(k.last_used_at).toLocaleDateString() : 'Never'}</td>
                  <td style={{ textAlign: 'right' }}>
                    {k.is_active && (
                      <button className="btn-danger" onClick={() => handleRevoke(k.id)} disabled={revoking === k.id}>
                        {revoking === k.id ? 'Revoking...' : 'Revoke'}
                      </button>
                    )}
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
