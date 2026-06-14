import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import type { Scan } from '../types'
import { StatusBadge } from '../components/StatusBadge'
import { SeverityBadge } from '../components/SeverityBadge'
import './Page.css'

export default function Dashboard() {
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api.scans.list(1, 5)
      .then(setScans)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  const totals = scans.reduce((acc, s) => ({
    critical: acc.critical + s.summary.critical,
    high: acc.high + s.summary.high,
    medium: acc.medium + s.summary.medium,
    low: acc.low + s.summary.low,
    total: acc.total + s.summary.total_findings,
  }), { critical: 0, high: 0, medium: 0, low: 0, total: 0 })

  if (loading) return <div className="loading">Loading...</div>
  if (error) return <div className="error">{error}</div>

  return (
    <div>
      <h1 className="page-title">Dashboard</h1>

      <div className="stats-grid">
        <div className="stat-card critical">
          <div className="stat-value">{totals.critical}</div>
          <div className="stat-label">Critical</div>
        </div>
        <div className="stat-card high">
          <div className="stat-value">{totals.high}</div>
          <div className="stat-label">High</div>
        </div>
        <div className="stat-card medium">
          <div className="stat-value">{totals.medium}</div>
          <div className="stat-label">Medium</div>
        </div>
        <div className="stat-card low">
          <div className="stat-value">{totals.low}</div>
          <div className="stat-label">Low</div>
        </div>
        <div className="stat-card info">
          <div className="stat-value">{totals.total}</div>
          <div className="stat-label">Total Findings</div>
        </div>
      </div>

      <div className="section">
        <div className="section-header">
          <h2>Recent Scans</h2>
          <Link to="/scans" className="view-all">View all →</Link>
        </div>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Target</th>
                <th>Status</th>
                <th>Critical</th>
                <th>High</th>
                <th>Started</th>
              </tr>
            </thead>
            <tbody>
              {scans.map(scan => (
                <tr key={scan.id}>
                  <td><Link to={`/scans/${scan.id}`}>{scan.target}</Link></td>
                  <td><StatusBadge status={scan.status} /></td>
                  <td>{scan.summary.critical > 0 ? <SeverityBadge severity="critical" /> : '—'}</td>
                  <td>{scan.summary.high}</td>
                  <td className="muted">{new Date(scan.started_at).toLocaleString()}</td>
                </tr>
              ))}
              {scans.length === 0 && (
                <tr><td colSpan={5} className="empty">No scans yet. <Link to="/scans">Start a scan →</Link></td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
