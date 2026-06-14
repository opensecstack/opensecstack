import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import axios from 'axios'
import Layout from '@/components/Layout'
import PageHeader from '@/components/PageHeader'
import Card from '@/components/Card'

interface AuditEntry {
  id: string
  event_type: string
  actor: string
  client_id: string
  ip_address: string
  user_agent: string
  metadata: unknown
  created_at: string
}

const EVENT_COLORS: Record<string, string> = {
  'login.success':       '#16a34a',
  'login.failure':       '#dc2626',
  'user.registered':     '#2563eb',
  'user.deactivated':    '#d97706',
  'user.password_reset': '#7c3aed',
  'client.created':      '#0891b2',
  'client.deleted':      '#dc2626',
  'session.revoked':     '#d97706',
}

function eventColor(type: string) {
  return EVENT_COLORS[type] ?? '#6b7280'
}

async function fetchAudit(limit: number): Promise<AuditEntry[]> {
  const { data } = await axios.get(`/api/v1/admin/audit?limit=${limit}`, {
    headers: { Authorization: `Bearer ${localStorage.getItem('sinauth_token')}` },
  })
  return data ?? []
}

export default function AuditLog() {
  const [limit, setLimit] = useState(100)
  const { data = [], isLoading, error, refetch } = useQuery({
    queryKey: ['audit', limit],
    queryFn: () => fetchAudit(limit),
    refetchInterval: 30_000,
  })

  return (
    <Layout>
      <PageHeader title="Audit Log" />
      <Card>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginBottom: 16 }}>
          <select value={limit} onChange={e => setLimit(Number(e.target.value))}
            style={{ border: '1px solid #d1d5db', borderRadius: 6, padding: '6px 10px', fontSize: 13 }}>
            <option value={50}>Last 50</option>
            <option value={100}>Last 100</option>
            <option value={250}>Last 250</option>
            <option value={500}>Last 500</option>
          </select>
          <button onClick={() => refetch()}
            style={{ background: '#f3f4f6', border: '1px solid #d1d5db', borderRadius: 6, padding: '6px 14px', fontSize: 13, cursor: 'pointer' }}>
            Refresh
          </button>
        </div>

        {isLoading && <p style={{ color: '#6b7280' }}>Loading…</p>}
        {error && <p style={{ color: '#dc2626' }}>Failed to load audit log.</p>}

        {!isLoading && !error && (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr style={{ background: '#f9fafb', borderBottom: '1px solid #e5e7eb' }}>
                  {['Time', 'Event', 'Actor', 'Client', 'IP Address'].map(h => (
                    <th key={h} style={{ padding: '8px 12px', textAlign: 'left', fontWeight: 600, color: '#374151', whiteSpace: 'nowrap' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.length === 0 ? (
                  <tr><td colSpan={5} style={{ padding: '32px', textAlign: 'center', color: '#9ca3af' }}>No audit events yet.</td></tr>
                ) : data.map(e => (
                  <tr key={e.id} style={{ borderBottom: '1px solid #f3f4f6' }}>
                    <td style={{ padding: '8px 12px', color: '#6b7280', whiteSpace: 'nowrap' }}>
                      {new Date(e.created_at).toLocaleString()}
                    </td>
                    <td style={{ padding: '8px 12px' }}>
                      <span style={{
                        background: eventColor(e.event_type) + '18',
                        color: eventColor(e.event_type),
                        borderRadius: 4, padding: '2px 8px', fontWeight: 600, fontSize: 12,
                      }}>{e.event_type}</span>
                    </td>
                    <td style={{ padding: '8px 12px', color: '#111827' }}>{e.actor || '—'}</td>
                    <td style={{ padding: '8px 12px', color: '#6b7280' }}>{e.client_id || '—'}</td>
                    <td style={{ padding: '8px 12px', color: '#6b7280', fontFamily: 'monospace' }}>{e.ip_address || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </Layout>
  )
}
