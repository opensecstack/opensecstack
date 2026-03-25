import { useState, useEffect } from 'react'
import { api } from '../api'
import type { AuditEntry } from '../types'
import { StatusBadge } from '../components/StatusBadge'
import './Page.css'

const PER_PAGE = 25

export default function AuditLog() {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    load(page)
  }, [page])

  async function load(p: number) {
    setLoading(true)
    setError(null)
    try {
      const { entries: data, total: t } = await api.audit.list({ page: p, per_page: PER_PAGE })
      setEntries(data)
      setTotal(t)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load audit log')
    } finally {
      setLoading(false)
    }
  }

  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE))

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Audit Log</h1>
        <span className="muted" style={{ fontSize: 13 }}>{total} total entries</span>
      </div>

      {error && <p className="error">{error}</p>}

      {loading ? (
        <p className="loading">Loading audit log...</p>
      ) : entries.length === 0 ? (
        <p className="empty">No audit entries found.</p>
      ) : (
        <>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Action</th>
                  <th>Actor</th>
                  <th>Resource Type</th>
                  <th>Resource ID</th>
                  <th>Risk</th>
                  <th>Chain Hash</th>
                </tr>
              </thead>
              <tbody>
                {entries.map(entry => (
                  <tr key={entry.id}>
                    <td className="muted" style={{ whiteSpace: 'nowrap', fontSize: 12 }}>
                      {new Date(entry.timestamp).toLocaleString()}
                    </td>
                    <td style={{ fontFamily: 'monospace', fontSize: 12 }}>{entry.action}</td>
                    <td style={{ fontSize: 13 }}>{entry.actor}</td>
                    <td className="muted" style={{ fontSize: 12 }}>{entry.resource_type}</td>
                    <td
                      className="muted"
                      style={{ fontFamily: 'monospace', fontSize: 11 }}
                      title={entry.resource_id ?? undefined}
                    >
                      {entry.resource_id ? entry.resource_id.slice(0, 8) + '...' : '—'}
                    </td>
                    <td><StatusBadge status={entry.risk_class} /></td>
                    <td
                      style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--text-muted)' }}
                      title={entry.chain_hash}
                    >
                      {entry.chain_hash.slice(0, 8)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {totalPages > 1 && (
            <div style={{ display: 'flex', gap: 8, marginTop: 16, alignItems: 'center' }}>
              <button
                className="btn-secondary"
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1 || loading}
                style={{ padding: '6px 12px' }}
              >
                Previous
              </button>
              <span className="muted" style={{ fontSize: 13 }}>
                Page {page} of {totalPages}
              </span>
              <button
                className="btn-secondary"
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={page === totalPages || loading}
                style={{ padding: '6px 12px' }}
              >
                Next
              </button>
            </div>
          )}
        </>
      )}
    </div>
  )
}
