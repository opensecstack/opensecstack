import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import type { Finding, Severity } from '../types'
import { SeverityBadge } from '../components/SeverityBadge'
import './Page.css'

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

export default function Findings() {
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [filter, setFilter] = useState<Severity | ''>('')

  useEffect(() => {
    api.findings.list({ severity: filter || undefined })
      .then(setFindings)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [filter])

  if (loading) return <div className="loading">Loading...</div>

  return (
    <div>
      <h1 className="page-title">Findings</h1>

      {error && <div className="error">{error}</div>}

      <div className="filter-bar">
        <button className={`filter-btn ${filter === '' ? 'active' : ''}`} onClick={() => setFilter('')}>All</button>
        {SEVERITIES.map(s => (
          <button key={s} className={`filter-btn ${filter === s ? 'active' : ''}`} onClick={() => setFilter(s)}>
            {s.charAt(0).toUpperCase() + s.slice(1)}
          </button>
        ))}
      </div>

      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr><th>Severity</th><th>OWASP</th><th>Title</th><th>Endpoint</th><th>Scan</th></tr>
          </thead>
          <tbody>
            {findings.map(f => (
              <tr key={f.id}>
                <td><SeverityBadge severity={f.severity} /></td>
                <td className="muted">{f.owasp_id}</td>
                <td>{f.title}</td>
                <td className="muted">{f.endpoint_method} {f.endpoint_path}</td>
                <td><Link to={`/scans/${f.scan_id}`}>View scan →</Link></td>
              </tr>
            ))}
            {findings.length === 0 && (
              <tr><td colSpan={5} className="empty">No findings.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
