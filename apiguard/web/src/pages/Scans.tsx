import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import type { Scan } from '../types'
import { StatusBadge } from '../components/StatusBadge'
import './Page.css'

const OWASP_MODULES = [
  { id: 'a1_bola',              label: 'A1: Broken Object Level Authorization' },
  { id: 'a2_auth',              label: 'A2: Broken Authentication' },
  { id: 'a3_mass_assignment',   label: 'A3: Mass Assignment' },
  { id: 'a4_rate_limit',        label: 'A4: Rate Limiting' },
  { id: 'a5_function_auth',     label: 'A5: Function Auth' },
  { id: 'a6_sensitive_flows',   label: 'A6: Sensitive Flows' },
  { id: 'a7_ssrf',              label: 'A7: SSRF' },
  { id: 'a8_misconfiguration',  label: 'A8: Misconfiguration' },
  { id: 'a9_inventory',         label: 'A9: Inventory Management' },
  { id: 'a10_unsafe_consumption', label: 'A10: Unsafe Consumption' },
]

const ALL_MODULE_IDS = OWASP_MODULES.map(m => m.id)

export default function Scans() {
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ target: '', spec_url: '' })
  const [specMode, setSpecMode] = useState<'url' | 'upload'>('url')
  const [specFile, setSpecFile] = useState<File | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [selectedModules, setSelectedModules] = useState<Set<string>>(new Set(ALL_MODULE_IDS))

  const load = () => {
    api.scans.list()
      .then(setScans)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  const toggleModule = (id: string) => {
    setSelectedModules(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!form.target) return
    if (specMode === 'url' && !form.spec_url) return
    if (specMode === 'upload' && !specFile) return
    setSubmitting(true)
    try {
      let scanPayload: { target: string; spec_url?: string; spec_path?: string; modules?: string[] }
      const modules = Array.from(selectedModules)
      if (specMode === 'upload') {
        const { spec_path } = await api.specs.upload(specFile!)
        scanPayload = { target: form.target, spec_path, modules }
      } else {
        scanPayload = { target: form.target, spec_url: form.spec_url, modules }
      }
      await api.scans.create(scanPayload)
      setShowForm(false)
      setForm({ target: '', spec_url: '' })
      setSpecFile(null)
      setSpecMode('url')
      setSelectedModules(new Set(ALL_MODULE_IDS))
      setShowAdvanced(false)
      load()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to create scan')
    } finally {
      setSubmitting(false)
    }
  }

  if (loading) return <div className="loading">Loading...</div>

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Scans</h1>
        <button className="btn-primary" onClick={() => setShowForm(!showForm)}>
          {showForm ? 'Cancel' : '+ New Scan'}
        </button>
      </div>

      {error && <div className="error">{error}</div>}

      {showForm && (
        <form onSubmit={handleSubmit} className="card form-card">
          <h3>New Scan</h3>
          <div className="form-row">
            <label>Target URL</label>
            <input
              type="url" placeholder="https://api.example.com"
              value={form.target} onChange={e => setForm({ ...form, target: e.target.value })}
              required
            />
          </div>
          <div className="form-row">
            <label>OpenAPI Spec</label>
            <div className="toggle-group">
              <button
                type="button"
                className={`toggle-btn ${specMode === 'url' ? 'active' : ''}`}
                onClick={() => setSpecMode('url')}
              >URL</button>
              <button
                type="button"
                className={`toggle-btn ${specMode === 'upload' ? 'active' : ''}`}
                onClick={() => setSpecMode('upload')}
              >Upload file</button>
            </div>
            {specMode === 'url' ? (
              <input
                type="url" placeholder="https://api.example.com/openapi.json"
                value={form.spec_url} onChange={e => setForm({ ...form, spec_url: e.target.value })}
                required
              />
            ) : (
              <input
                type="file" accept=".yaml,.yml,.json"
                onChange={e => setSpecFile(e.target.files?.[0] ?? null)}
                required
              />
            )}
          </div>

          <div className="advanced-section">
            <button
              type="button"
              className="advanced-toggle"
              onClick={() => setShowAdvanced(!showAdvanced)}
              aria-expanded={showAdvanced}
            >
              <span className={`advanced-chevron ${showAdvanced ? 'open' : ''}`}>▶</span>
              Advanced Options
            </button>

            {showAdvanced && (
              <div className="advanced-body">
                <div className="modules-header">
                  <span className="modules-label">OWASP Modules</span>
                  <div className="modules-actions">
                    <button
                      type="button"
                      className="btn-link"
                      onClick={() => setSelectedModules(new Set(ALL_MODULE_IDS))}
                    >
                      Select All
                    </button>
                    <span className="modules-sep">·</span>
                    <button
                      type="button"
                      className="btn-link"
                      onClick={() => setSelectedModules(new Set())}
                    >
                      Clear All
                    </button>
                  </div>
                </div>
                <div className="modules-grid">
                  {OWASP_MODULES.map(mod => (
                    <label key={mod.id} className="module-checkbox">
                      <input
                        type="checkbox"
                        checked={selectedModules.has(mod.id)}
                        onChange={() => toggleModule(mod.id)}
                      />
                      <span>{mod.label}</span>
                    </label>
                  ))}
                </div>
                <div className="modules-count">
                  {selectedModules.size} of {OWASP_MODULES.length} modules selected
                </div>
              </div>
            )}
          </div>

          <button type="submit" className="btn-primary" disabled={submitting || selectedModules.size === 0}>
            {submitting ? 'Starting...' : 'Start Scan'}
          </button>
          {selectedModules.size === 0 && (
            <span className="form-hint">Select at least one module to run the scan.</span>
          )}
        </form>
      )}

      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Target</th>
              <th>Status</th>
              <th>Findings</th>
              <th>Started</th>
              <th>Duration</th>
            </tr>
          </thead>
          <tbody>
            {scans.map(scan => {
              const duration = scan.completed_at
                ? Math.round((new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 1000)
                : null
              return (
                <tr key={scan.id}>
                  <td><Link to={`/scans/${scan.id}`}>{scan.target}</Link></td>
                  <td><StatusBadge status={scan.status} /></td>
                  <td>{scan.summary.total_findings}</td>
                  <td className="muted">{new Date(scan.started_at).toLocaleString()}</td>
                  <td className="muted">{duration != null ? `${duration}s` : '—'}</td>
                </tr>
              )
            })}
            {scans.length === 0 && (
              <tr><td colSpan={5} className="empty">No scans yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
