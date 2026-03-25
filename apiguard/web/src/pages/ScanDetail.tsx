import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { api } from '../api'
import type { Scan, Finding } from '../types'
import { StatusBadge } from '../components/StatusBadge'
import { SeverityBadge } from '../components/SeverityBadge'
import './Page.css'

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>()
  const [scan, setScan] = useState<Scan | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<string | null>(null)

  useEffect(() => {
    if (!id) return
    Promise.all([api.scans.get(id), api.scans.findings(id)])
      .then(([s, f]) => { setScan(s); setFindings(f) })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [id])

  if (loading) return <div className="loading">Loading...</div>
  if (error) return <div className="error">{error}</div>
  if (!scan) return null

  return (
    <div>
      <div className="breadcrumb"><Link to="/scans">Scans</Link> / {scan.target}</div>
      <div className="page-header">
        <h1 className="page-title">{scan.target}</h1>
        <StatusBadge status={scan.status} />
      </div>

      <div className="stats-grid">
        {(['critical', 'high', 'medium', 'low', 'info'] as const).map(sev => (
          <div key={sev} className={`stat-card ${sev}`}>
            <div className="stat-value">{scan.summary[sev as keyof typeof scan.summary] ?? 0}</div>
            <div className="stat-label" style={{ textTransform: 'capitalize' }}>{sev}</div>
          </div>
        ))}
      </div>

      <div className="section">
        <h2>Findings ({findings.length})</h2>
        <div className="findings-list">
          {findings.map(f => (
            <div key={f.id} className="finding-card" onClick={() => setExpanded(expanded === f.id ? null : f.id)}>
              <div className="finding-header">
                <SeverityBadge severity={f.severity} />
                <span className="finding-owasp">{f.owasp_id}</span>
                <span className="finding-title">{f.title}</span>
                <span className="finding-endpoint muted">{f.endpoint_method} {f.endpoint_path}</span>
              </div>
              {expanded === f.id && (
                <div className="finding-detail">
                  <p>{f.description}</p>
                  {f.cvss_score > 0 && <div className="meta">CVSS: <strong>{f.cvss_score.toFixed(1)}</strong></div>}
                  <div className="evidence">
                    <div className="evidence-row"><span>Request:</span><code>{f.evidence.request}</code></div>
                    <div className="evidence-row"><span>Response:</span><code>{f.evidence.response}</code></div>
                  </div>
                  <div className="remediation"><strong>Remediation:</strong> {f.remediation}</div>
                </div>
              )}
            </div>
          ))}
          {findings.length === 0 && <div className="empty">No findings for this scan.</div>}
        </div>
      </div>
    </div>
  )
}
