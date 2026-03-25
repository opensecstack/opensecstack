import { useState, useEffect, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import type { Organisation } from '../types'
import './Page.css'

const INDUSTRIES = [
  'energy', 'transport', 'banking', 'financial_markets', 'health',
  'drinking_water', 'waste_water', 'digital_infra', 'ict_services',
  'public_admin', 'space', 'postal', 'waste_mgmt', 'chemicals',
  'food', 'manufacturing', 'digital_providers', 'research',
]

const SIZES = ['micro', 'small', 'medium', 'large'] as const

export default function OrganisationList() {
  const [orgs, setOrgs] = useState<Organisation[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showForm, setShowForm] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  const [name, setName] = useState('')
  const [industry, setIndustry] = useState('energy')
  const [country, setCountry] = useState('')
  const [size, setSize] = useState<string>('medium')
  const [entityType, setEntityType] = useState<string>('important')
  const [contactEmail, setContactEmail] = useState('')

  useEffect(() => {
    load()
  }, [])

  async function load() {
    setLoading(true)
    setError(null)
    try {
      const data = await api.organisations.list()
      setOrgs(data)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load organisations')
    } finally {
      setLoading(false)
    }
  }

  async function handleCreate(e: FormEvent) {
    e.preventDefault()
    if (!name.trim() || !country.trim()) return
    setSubmitting(true)
    setFormError(null)
    try {
      const org = await api.organisations.create({
        name: name.trim(),
        industry,
        country: country.trim().toUpperCase(),
        size,
        entity_type: entityType,
        contact_email: contactEmail.trim() || undefined,
      })
      setOrgs(prev => [org, ...prev])
      setShowForm(false)
      setName('')
      setCountry('')
      setContactEmail('')
    } catch (err: unknown) {
      setFormError(err instanceof Error ? err.message : 'Failed to create organisation')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Organisations</h1>
        <button className="btn-primary" onClick={() => setShowForm(v => !v)}>
          {showForm ? 'Cancel' : '+ New Organisation'}
        </button>
      </div>

      {showForm && (
        <div className="card form-card" style={{ marginBottom: 24 }}>
          <h3>New Organisation</h3>
          {formError && <p className="error">{formError}</p>}
          <form onSubmit={handleCreate}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 24px' }}>
              <div className="form-row">
                <label>Name *</label>
                <input
                  value={name}
                  onChange={e => setName(e.target.value)}
                  placeholder="Acme Energy GmbH"
                  required
                  disabled={submitting}
                />
              </div>
              <div className="form-row">
                <label>Country (ISO 3166-1) *</label>
                <input
                  value={country}
                  onChange={e => setCountry(e.target.value)}
                  placeholder="DE"
                  maxLength={2}
                  required
                  disabled={submitting}
                />
              </div>
              <div className="form-row">
                <label>Industry *</label>
                <select value={industry} onChange={e => setIndustry(e.target.value)} disabled={submitting}>
                  {INDUSTRIES.map(i => (
                    <option key={i} value={i}>{i.replace(/_/g, ' ')}</option>
                  ))}
                </select>
              </div>
              <div className="form-row">
                <label>Size *</label>
                <select value={size} onChange={e => setSize(e.target.value)} disabled={submitting}>
                  {SIZES.map(s => <option key={s} value={s}>{s}</option>)}
                </select>
              </div>
              <div className="form-row">
                <label>Entity Type *</label>
                <select value={entityType} onChange={e => setEntityType(e.target.value)} disabled={submitting}>
                  <option value="important">Important</option>
                  <option value="essential">Essential</option>
                </select>
              </div>
              <div className="form-row">
                <label>Contact Email</label>
                <input
                  type="email"
                  value={contactEmail}
                  onChange={e => setContactEmail(e.target.value)}
                  placeholder="compliance@example.com"
                  disabled={submitting}
                />
              </div>
            </div>
            <button className="btn-primary" type="submit" disabled={submitting || !name.trim() || !country.trim()}>
              {submitting ? 'Creating...' : 'Create Organisation'}
            </button>
          </form>
        </div>
      )}

      {error && <p className="error">{error}</p>}
      {loading ? (
        <p className="loading">Loading organisations...</p>
      ) : orgs.length === 0 ? (
        <p className="empty">No organisations yet. Create one to get started.</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Industry</th>
                <th>Country</th>
                <th>Size</th>
                <th>Entity Type</th>
                <th>Created</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {orgs.map(org => (
                <tr key={org.id}>
                  <td style={{ fontWeight: 500 }}>{org.name}</td>
                  <td className="muted">{org.industry}</td>
                  <td className="muted">{org.country}</td>
                  <td className="muted">{org.size}</td>
                  <td className="muted">{org.entity_type}</td>
                  <td className="muted">{new Date(org.created_at).toLocaleDateString()}</td>
                  <td>
                    <Link to={`/organisations/${org.id}/assessments`} className="btn-primary" style={{ padding: '4px 12px', fontSize: 13 }}>
                      Assessments
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
