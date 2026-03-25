import { useEffect, useState } from 'react'
import { api } from '../api'
import type { AuditEntry } from '../types'
import './Page.css'

const PER_PAGE = 25

function validateChain(entries: AuditEntry[]): boolean {
  // entries are ordered newest-first; prev_hash of entry[i] should equal chain_hash of entry[i+1]
  for (let i = 0; i < entries.length - 1; i++) {
    if (entries[i].prev_hash && entries[i].prev_hash !== entries[i + 1].chain_hash) {
      return false
    }
  }
  return true
}

export default function AuditLog() {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [chainValid, setChainValid] = useState<boolean | null>(null)

  useEffect(() => {
    setLoading(true)
    api.audit.list({ page, per_page: PER_PAGE })
      .then(({ entries: data, total: t }) => {
        setEntries(data)
        setTotal(t)
        setChainValid(data.length > 1 ? validateChain(data) : null)
      })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [page])

  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE))

  if (loading) return <div className="loading">Loading...</div>

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Audit Log</h1>
        {chainValid !== null && (
          <span className={`badge ${chainValid ? 'badge-success' : 'badge-danger'}`}>
            {chainValid ? 'chain valid' : 'chain broken'}
          </span>
        )}
      </div>

      {error && <div className="error">{error}</div>}

      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Action</th>
              <th>Actor</th>
              <th>Resource</th>
              <th>Result</th>
            </tr>
          </thead>
          <tbody>
            {entries.map(e => (
              <tr key={e.id}>
                <td className="muted">{new Date(e.created_at).toLocaleString()}</td>
                <td><code>{e.action}</code></td>
                <td className="muted">{e.actor_id}</td>
                <td className="muted">
                  {e.resource_type}{e.resource_id ? ` / ${e.resource_id.slice(0, 8)}…` : ''}
                </td>
                <td className="muted" title={e.chain_hash}>
                  {e.chain_hash.slice(0, 8)}…
                </td>
              </tr>
            ))}
            {entries.length === 0 && (
              <tr><td colSpan={5} className="empty">No audit log entries.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
        <div className="pagination">
          <button className="btn-secondary" onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}>
            Previous
          </button>
          <span className="page-info">Page {page} of {totalPages}</span>
          <button className="btn-secondary" onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}>
            Next
          </button>
        </div>
      )}
    </div>
  )
}
