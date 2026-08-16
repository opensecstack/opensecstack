import { useEffect, useRef, useState } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import { api } from '../api'
import type { Scan, Finding } from '../types'
import { StatusBadge } from '../components/StatusBadge'
import { SeverityBadge } from '../components/SeverityBadge'
import './Page.css'

const ACTIVE_STATUSES = new Set(['pending', 'running'])
const TERMINAL_STATUSES = new Set(['completed', 'failed', 'cancelled'])

const MODULE_LABELS: Record<string, string> = {
  a1_bola:               'A1: BOLA',
  a2_auth:               'A2: Auth',
  a3_mass_assignment:    'A3: Mass Assignment',
  a4_rate_limit:         'A4: Rate Limiting',
  a5_function_auth:      'A5: Function Auth',
  a6_sensitive_flows:    'A6: Sensitive Flows',
  a7_ssrf:               'A7: SSRF',
  a8_misconfiguration:   'A8: Misconfiguration',
  a9_inventory:          'A9: Inventory',
  a10_unsafe_consumption:'A10: Unsafe Consumption',
}

type ReportFormat = 'json' | 'html'

interface ReportState {
  format: ReportFormat
  visible: boolean
  loading: boolean
  error: string | null
  jsonData: string | null
  htmlUrl: string | null
}

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [scan, setScan] = useState<Scan | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<string | null>(null)
  const [cancelling, setCancelling] = useState(false)
  const [report, setReport] = useState<ReportState>({
    format: 'json',
    visible: false,
    loading: false,
    error: null,
    jsonData: null,
    htmlUrl: null,
  })

  // Keep a ref to the current scan status so the polling interval can read
  // the latest value without being re-created on every status change.
  const scanRef = useRef<Scan | null>(null)
  scanRef.current = scan

  // Keep a ref to the current object URL so we can revoke the previous one
  // before creating a new one (avoids memory leaks).
  const htmlBlobUrlRef = useRef<string | null>(null)

  const loadFindings = (scanId: string) => {
    api.scans.findings(scanId)
      .then(setFindings)
      .catch(() => { /* findings load errors are non-fatal */ })
  }

  useEffect(() => {
    if (!id) return

    // Initial load
    Promise.all([api.scans.get(id), api.scans.findings(id)])
      .then(([s, f]) => { setScan(s); setFindings(f) })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [id])

  // Polling effect — starts when scan is active, stops when terminal
  useEffect(() => {
    if (!id) return
    if (!scan) return
    if (!ACTIVE_STATUSES.has(scan.status)) return

    const intervalId = setInterval(async () => {
      try {
        const updated = await api.scans.get(id)
        setScan(updated)

        if (TERMINAL_STATUSES.has(updated.status)) {
          clearInterval(intervalId)
          if (updated.status === 'completed') {
            loadFindings(id)
          }
        }
      } catch {
        // Polling errors are transient — keep retrying
      }
    }, 3000)

    return () => clearInterval(intervalId)
  }, [id, scan?.status])  // Re-run if the status changes so we stop when terminal

  // Revoke blob URLs on unmount to avoid memory leaks
  useEffect(() => {
    return () => {
      if (htmlBlobUrlRef.current) {
        URL.revokeObjectURL(htmlBlobUrlRef.current)
      }
    }
  }, [])

  const handleCancel = async () => {
    if (!id || cancelling) return
    setCancelling(true)
    try {
      await api.scans.cancel(id)
      navigate('/scans')
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to cancel scan')
      setCancelling(false)
    }
  }

  const handleToggleReport = async () => {
    if (!id) return

    // If already visible, hide it
    if (report.visible) {
      setReport(r => ({ ...r, visible: false }))
      return
    }

    setReport(r => ({ ...r, visible: true, loading: true, error: null }))
    try {
      const result = await api.scans.getReport(id, report.format)
      if (report.format === 'html') {
        const blob = result as Blob
        if (htmlBlobUrlRef.current) URL.revokeObjectURL(htmlBlobUrlRef.current)
        const url = URL.createObjectURL(blob)
        htmlBlobUrlRef.current = url
        setReport(r => ({ ...r, loading: false, htmlUrl: url, jsonData: null }))
      } else {
        const { data } = result as { data: string; format: string }
        setReport(r => ({ ...r, loading: false, jsonData: data, htmlUrl: null }))
      }
    } catch (e: unknown) {
      setReport(r => ({
        ...r,
        loading: false,
        error: e instanceof Error ? e.message : 'Failed to load report',
      }))
    }
  }

  const handleFormatChange = (fmt: ReportFormat) => {
    // Changing format resets the loaded preview so it re-fetches on next toggle
    if (htmlBlobUrlRef.current) {
      URL.revokeObjectURL(htmlBlobUrlRef.current)
      htmlBlobUrlRef.current = null
    }
    setReport(r => ({
      ...r,
      format: fmt,
      visible: false,
      jsonData: null,
      htmlUrl: null,
      error: null,
    }))
  }

  const downloadReport = () => {
    if (!id) return
    const token = localStorage.getItem('apiguard_token')
    const url = `/api/v1/scans/${id}/report?format=${report.format}`
    // Open in new tab — browser will handle the download based on Content-Disposition
    const a = document.createElement('a')
    a.href = url
    if (token) {
      // For authenticated downloads we redirect — the API uses Bearer so the
      // browser fetch won't include the auth header for simple <a> tags.
      // Use the existing getReport to get the blob and trigger a save.
      api.scans.getReport(id, report.format).then(result => {
        const blob = result instanceof Blob ? result : new Blob([
          (result as { data: string }).data,
        ], { type: report.format === 'json' ? 'application/json' : 'text/html' })
        const blobUrl = URL.createObjectURL(blob)
        const link = document.createElement('a')
        link.href = blobUrl
        link.download = `apiguard-report-${id}.${report.format}`
        link.click()
        URL.revokeObjectURL(blobUrl)
      }).catch(() => { /* silently ignore */ })
    } else {
      a.download = `apiguard-report-${id}.${report.format}`
      a.click()
    }
  }

  // Parse JSON report data into a structured object for rendering
  const parsedJsonReport = (() => {
    if (!report.jsonData) return null
    try {
      return JSON.parse(report.jsonData)
    } catch {
      return null
    }
  })()

  if (loading) return <div className="loading">Loading...</div>
  if (error) return <div className="error">{error}</div>
  if (!scan) return null

  const isActive = ACTIVE_STATUSES.has(scan.status)
  const isCompleted = scan.status === 'completed'

  return (
    <div>
      <div className="breadcrumb"><Link to="/scans">Scans</Link> / {scan.target}</div>
      <div className="page-header">
        <h1 className="page-title">{scan.target}</h1>
        <div className="page-header-actions">
          <StatusBadge status={scan.status} />
          {isActive && (
            <button
              className="btn-danger"
              onClick={handleCancel}
              disabled={cancelling}
            >
              {cancelling ? 'Cancelling...' : 'Cancel Scan'}
            </button>
          )}
        </div>
      </div>

      {/* Active scan progress indicator */}
      {isActive && (
        <div className="scan-progress-banner">
          <span className="spinner" aria-hidden="true" />
          <span className="scan-progress-text">Scan in progress...</span>
          {scan.modules && scan.modules.length > 0 && (
            <div className="scan-modules-running">
              {scan.modules.map(mod => (
                <span key={mod} className="module-badge">
                  {MODULE_LABELS[mod] ?? mod}
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      <div className="stats-grid">
        {(['critical', 'high', 'medium', 'low', 'info'] as const).map(sev => (
          <div key={sev} className={`stat-card ${sev}`}>
            <div className="stat-value">{scan.summary[sev as keyof typeof scan.summary] ?? 0}</div>
            <div className="stat-label" style={{ textTransform: 'capitalize' }}>{sev}</div>
          </div>
        ))}
      </div>

      {/* Module badges when not active (informational) */}
      {!isActive && scan.modules && scan.modules.length > 0 && (
        <div className="scan-modules-info">
          <span className="scan-modules-info-label">Modules run:</span>
          {scan.modules.map(mod => (
            <span key={mod} className="module-badge module-badge-dim">
              {MODULE_LABELS[mod] ?? mod}
            </span>
          ))}
        </div>
      )}

      {/* Report preview section */}
      {isCompleted && (
        <div className="report-section">
          <div className="report-controls">
            <div className="toggle-group">
              <button
                type="button"
                className={`toggle-btn ${report.format === 'json' ? 'active' : ''}`}
                onClick={() => handleFormatChange('json')}
              >JSON</button>
              <button
                type="button"
                className={`toggle-btn ${report.format === 'html' ? 'active' : ''}`}
                onClick={() => handleFormatChange('html')}
              >HTML</button>
            </div>
            <button
              className="btn-primary"
              onClick={handleToggleReport}
              disabled={report.loading}
            >
              {report.loading
                ? 'Loading...'
                : report.visible
                  ? 'Hide Preview'
                  : 'Preview Report'}
            </button>
            <button className="btn-secondary" onClick={downloadReport}>
              Download
            </button>
          </div>

          {report.error && (
            <div className="error" style={{ marginTop: 12 }}>{report.error}</div>
          )}

          {report.visible && !report.loading && (
            <div className="report-preview">
              {report.format === 'html' && report.htmlUrl && (
                <iframe
                  src={report.htmlUrl}
                  sandbox="allow-same-origin"
                  className="report-iframe"
                  title="Report Preview"
                />
              )}
              {report.format === 'json' && report.jsonData && (
                <div className="report-json-preview">
                  {parsedJsonReport ? (
                    <JsonReportRenderer report={parsedJsonReport} />
                  ) : (
                    <pre className="report-raw-json">{report.jsonData}</pre>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}

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

// ---------------------------------------------------------------------------
// JSON Report Renderer — renders a structured preview of the JSON report
// ---------------------------------------------------------------------------

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

interface JsonReportRendererProps {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  report: Record<string, any>
}

function JsonReportRenderer({ report }: JsonReportRendererProps) {
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null)

  const findings: Record<string, unknown>[] = Array.isArray(report.findings)
    ? report.findings
    : []

  const summary: Record<string, number> = report.summary ?? {}

  const severityCounts = SEVERITY_ORDER.map(sev => ({
    sev,
    count: (summary[sev] ?? summary[`${sev}_count`] ?? 0) as number,
  }))

  const groupedBySeverity = SEVERITY_ORDER.reduce<Record<string, Record<string, unknown>[]>>(
    (acc, sev) => {
      acc[sev] = findings.filter(f => (f.severity as string)?.toLowerCase() === sev)
      return acc
    },
    {},
  )

  return (
    <div className="json-report">
      <h3 className="json-report-title">Report Summary</h3>

      <table className="table json-report-summary-table">
        <thead>
          <tr>
            {SEVERITY_ORDER.map(sev => (
              <th key={sev} style={{ textTransform: 'capitalize' }}>{sev}</th>
            ))}
            <th>Total</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            {severityCounts.map(({ sev, count }) => (
              <td key={sev} className={`severity-count severity-count-${sev}`}>{count}</td>
            ))}
            <td><strong>{findings.length}</strong></td>
          </tr>
        </tbody>
      </table>

      {SEVERITY_ORDER.map(sev => {
        const group = groupedBySeverity[sev]
        if (!group || group.length === 0) return null
        return (
          <div key={sev} className="json-report-group">
            <h4 className={`json-report-group-title severity-heading-${sev}`}>
              {sev.charAt(0).toUpperCase() + sev.slice(1)} ({group.length})
            </h4>
            {group.map((f, idx) => {
              const fid = (f.id as string) ?? `${sev}-${idx}`
              const isOpen = expandedFinding === fid
              return (
                <div
                  key={fid}
                  className="finding-card"
                  onClick={() => setExpandedFinding(isOpen ? null : fid)}
                >
                  <div className="finding-header">
                    <span className={`badge badge-sev-${sev}`}>{sev.toUpperCase()}</span>
                    <span className="finding-owasp">{f.owasp_id as string}</span>
                    <span className="finding-title">{f.title as string}</span>
                    <span className="finding-endpoint muted">
                      {f.endpoint_method as string} {f.endpoint_path as string}
                    </span>
                  </div>
                  {isOpen && (
                    <div className="finding-detail">
                      <p>{f.description as string}</p>
                      {(f.cvss_score as number) > 0 && (
                        <div className="meta">CVSS: <strong>{(f.cvss_score as number).toFixed(1)}</strong></div>
                      )}
                      {(f.remediation as string) && (
                        <div className="remediation"><strong>Remediation:</strong> {f.remediation as string}</div>
                      )}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )
      })}

      {findings.length === 0 && (
        <div className="empty">No findings in this report.</div>
      )}
    </div>
  )
}
