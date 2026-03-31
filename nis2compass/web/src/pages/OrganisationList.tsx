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

function validateEmail(v: string): string | null {
  if (!v) return null
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) ? null : 'Invalid email address'
}

function validateCountry(v: string): string | null {
  if (!v) return 'Country is required'
  return /^[A-Z]{2}$/.test(v.toUpperCase()) ? null : 'Must be a 2-letter ISO code (e.g. DE)'
}

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

  // Inline validation
  const [emailError, setEmailError] = useState<string | null>(null)
  const [countryError, setCountryError] = useState<string | null>(null)

  // Edit state
  const [editingId, setEditingId] = useState<string | null>(null)
  const [editName, setEditName] = useState('')
  const [editIndustry, setEditIndustry] = useState('energy')
  const [editCountry, setEditCountry] = useState('')
  const [editSize, setEditSize] = useState('medium')
  const [editEntityType, setEditEntityType] = useState('important')
  const [editEmail, setEditEmail] = useState('')
  const [editError, setEditError] = useState<string | null>(null)
  const [editEmailError, setEditEmailError] = useState<string | null>(null)
  const [editCountryError, setEditCountryError] = useState<string | null>(null)

  // Delete state
  const [deleting, setDeleting] = useState<string | null>(null)

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
    const cErr = validateCountry(country)
    const eErr = validateEmail(contactEmail)
    setCountryError(cErr)
    setEmailError(eErr)
    if (!name.trim() || cErr || eErr) return
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
      setEmailError(null)
      setCountryError(null)
    } catch (err: unknown) {
      setFormError(err instanceof Error ? err.message : 'Failed to create organisation')
    } finally {
      setSubmitting(false)
    }
  }

  function startEdit(org: Organisation) {
    setEditingId(org.id)
    setEditName(org.name)
    setEditIndustry(org.industry)
    setEditCountry(org.country)
    setEditSize(org.size)
    setEditEntityType(org.entity_type)
    setEditEmail(org.contact_email ?? '')
    setEditError(null)
    setEditEmailError(null)
    setEditCountryError(null)
  }

  async function handleSaveEdit(e: FormEvent) {
    e.preventDefault()
    if (!editingId) return
    const cErr = validateCountry(editCountry)
    const eErr = validateEmail(editEmail)
    setEditCountryError(cErr)
    setEditEmailError(eErr)
    if (!editName.trim() || cErr || eErr) return
    setSubmitting(true)
    setEditError(null)
    try {
      const updated = await api.organisations.patch(editingId, {
        name: editName.trim(),
        industry: editIndustry,
        country: editCountry.trim().toUpperCase(),
        size: editSize,
        entity_type: editEntityType,
        contact_email: editEmail.trim() || undefined,
      })
      setOrgs(prev => prev.map(o => o.id === editingId ? updated : o))
      setEditingId(null)
    } catch (err: unknown) {
      setEditError(err instanceof Error ? err.message : 'Failed to update organisation')
    } finally {
      setSubmitting(false)
    }
  }

  async function handleDelete(org: Organisation) {
    if (!window.confirm(`Delete "${org.name}"? This will delete all assessments and evidence.`)) return
    setDeleting(org.id)
    try {
      await api.organisations.delete(org.id)
      setOrgs(prev => prev.filter(o => o.id !== org.id))
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete organisation')
    } finally {
      setDeleting(null)
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
                  onChange={e => { setCountry(e.target.value); setCountryError(null) }}
                  onBlur={() => country && setCountryError(validateCountry(country))}
                  placeholder="DE"
                  maxLength={2}
                  required
                  disabled={submitting}
                  style={countryError ? { borderColor: '#ef4444' } : {}}
                />
                {countryError && <span style={{ color: '#f87171', fontSize: 12 }}>{countryError}</span>}
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
                  onChange={e => { setContactEmail(e.target.value); setEmailError(null) }}
                  onBlur={() => contactEmail && setEmailError(validateEmail(contactEmail))}
                  placeholder="compliance@example.com"
                  disabled={submitting}
                  style={emailError ? { borderColor: '#ef4444' } : {}}
                />
                {emailError && <span style={{ color: '#f87171', fontSize: 12 }}>{emailError}</span>}
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
              {orgs.map(org => editingId === org.id ? (
                <tr key={org.id}>
                  <td colSpan={7} style={{ padding: 0 }}>
                    <form onSubmit={handleSaveEdit} className="card" style={{ margin: 8, padding: 16 }}>
                      {editError && <p className="error">{editError}</p>}
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 80px 100px 110px', gap: '8px 12px', alignItems: 'end' }}>
                        <div className="form-row" style={{ marginBottom: 0 }}>
                          <label>Name *</label>
                          <input value={editName} onChange={e => setEditName(e.target.value)} required disabled={submitting} />
                        </div>
                        <div className="form-row" style={{ marginBottom: 0 }}>
                          <label>Industry</label>
                          <select value={editIndustry} onChange={e => setEditIndustry(e.target.value)} disabled={submitting}>
                            {INDUSTRIES.map(i => <option key={i} value={i}>{i.replace(/_/g, ' ')}</option>)}
                          </select>
                        </div>
                        <div className="form-row" style={{ marginBottom: 0 }}>
                          <label>Country *</label>
                          <input value={editCountry} onChange={e => { setEditCountry(e.target.value); setEditCountryError(null) }} maxLength={2} disabled={submitting} style={editCountryError ? { borderColor: '#ef4444' } : {}} />
                          {editCountryError && <span style={{ color: '#f87171', fontSize: 11 }}>{editCountryError}</span>}
                        </div>
                        <div className="form-row" style={{ marginBottom: 0 }}>
                          <label>Size</label>
                          <select value={editSize} onChange={e => setEditSize(e.target.value)} disabled={submitting}>
                            {SIZES.map(s => <option key={s} value={s}>{s}</option>)}
                          </select>
                        </div>
                        <div className="form-row" style={{ marginBottom: 0 }}>
                          <label>Entity</label>
                          <select value={editEntityType} onChange={e => setEditEntityType(e.target.value)} disabled={submitting}>
                            <option value="important">Important</option>
                            <option value="essential">Essential</option>
                          </select>
                        </div>
                      </div>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 12, marginTop: 8, alignItems: 'end' }}>
                        <div className="form-row" style={{ marginBottom: 0 }}>
                          <label>Contact Email</label>
                          <input type="email" value={editEmail} onChange={e => { setEditEmail(e.target.value); setEditEmailError(null) }} onBlur={() => editEmail && setEditEmailError(validateEmail(editEmail))} disabled={submitting} style={editEmailError ? { borderColor: '#ef4444' } : {}} />
                          {editEmailError && <span style={{ color: '#f87171', fontSize: 11 }}>{editEmailError}</span>}
                        </div>
                        <div style={{ display: 'flex', gap: 8 }}>
                          <button className="btn-primary" type="submit" disabled={submitting || !editName.trim()}>
                            {submitting ? 'Saving...' : 'Save'}
                          </button>
                          <button className="btn-secondary" type="button" onClick={() => setEditingId(null)} disabled={submitting}>
                            Cancel
                          </button>
                        </div>
                      </div>
                    </form>
                  </td>
                </tr>
              ) : (
                <tr key={org.id} style={{ opacity: deleting === org.id ? 0.5 : 1 }}>
                  <td style={{ fontWeight: 500 }}>{org.name}</td>
                  <td className="muted">{org.industry}</td>
                  <td className="muted">{org.country}</td>
                  <td className="muted">{org.size}</td>
                  <td className="muted">{org.entity_type}</td>
                  <td className="muted">{new Date(org.created_at).toLocaleDateString()}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    <Link to={`/organisations/${org.id}/assessments`} className="btn-primary" style={{ padding: '4px 12px', fontSize: 13, marginRight: 6 }}>
                      Assessments
                    </Link>
                    <button className="btn-icon" style={{ marginRight: 6 }} onClick={() => startEdit(org)}>Edit</button>
                    <button className="btn-danger" onClick={() => handleDelete(org)} disabled={deleting === org.id}>
                      {deleting === org.id ? '...' : 'Delete'}
                    </button>
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
