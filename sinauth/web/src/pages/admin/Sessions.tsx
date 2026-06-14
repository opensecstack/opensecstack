import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import axios from 'axios'
import Layout from '@/components/Layout'
import PageHeader from '@/components/PageHeader'
import Card from '@/components/Card'

interface Session {
  id: string
  user_id: string
  username: string
  created_at: string
  expires_at: string
}

function authHeaders() {
  return { Authorization: `Bearer ${localStorage.getItem('sinauth_token')}` }
}

async function fetchSessions(): Promise<Session[]> {
  const { data } = await axios.get('/api/v1/admin/sessions', { headers: authHeaders() })
  return data ?? []
}

async function revokeSession(id: string) {
  await axios.delete(`/api/v1/admin/sessions/${id}`, { headers: authHeaders() })
}

export default function Sessions() {
  const qc = useQueryClient()
  const [confirming, setConfirming] = useState<string | null>(null)
  const { data = [], isLoading, error } = useQuery({
    queryKey: ['sessions'],
    queryFn: fetchSessions,
    refetchInterval: 30_000,
  })
  const revoke = useMutation({
    mutationFn: revokeSession,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['sessions'] }); setConfirming(null) },
  })

  return (
    <Layout>
      <PageHeader title={`Active Sessions (${data.length})`} />
      <Card>
        {isLoading && <p style={{ color: '#6b7280' }}>Loading…</p>}
        {error && <p style={{ color: '#dc2626' }}>Failed to load sessions.</p>}

        {!isLoading && !error && (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr style={{ background: '#f9fafb', borderBottom: '1px solid #e5e7eb' }}>
                  {['Username', 'Session ID', 'Started', 'Expires', ''].map(h => (
                    <th key={h} style={{ padding: '8px 12px', textAlign: 'left', fontWeight: 600, color: '#374151' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.length === 0 ? (
                  <tr><td colSpan={5} style={{ padding: '32px', textAlign: 'center', color: '#9ca3af' }}>No active sessions.</td></tr>
                ) : data.map(s => (
                  <tr key={s.id} style={{ borderBottom: '1px solid #f3f4f6' }}>
                    <td style={{ padding: '8px 12px', fontWeight: 500, color: '#111827' }}>{s.username}</td>
                    <td style={{ padding: '8px 12px', color: '#6b7280', fontFamily: 'monospace', fontSize: 11 }}>{s.id.slice(0, 16)}…</td>
                    <td style={{ padding: '8px 12px', color: '#6b7280', whiteSpace: 'nowrap' }}>{new Date(s.created_at).toLocaleString()}</td>
                    <td style={{ padding: '8px 12px', color: '#6b7280', whiteSpace: 'nowrap' }}>{new Date(s.expires_at).toLocaleString()}</td>
                    <td style={{ padding: '8px 12px', textAlign: 'right' }}>
                      {confirming === s.id ? (
                        <span style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                          <button onClick={() => revoke.mutate(s.id)} disabled={revoke.isPending}
                            style={{ background: '#dc2626', color: 'white', border: 'none', borderRadius: 6, padding: '4px 12px', cursor: 'pointer', fontSize: 12 }}>
                            Confirm
                          </button>
                          <button onClick={() => setConfirming(null)}
                            style={{ background: '#f3f4f6', border: '1px solid #d1d5db', borderRadius: 6, padding: '4px 12px', cursor: 'pointer', fontSize: 12 }}>
                            Cancel
                          </button>
                        </span>
                      ) : (
                        <button onClick={() => setConfirming(s.id)}
                          style={{ background: 'transparent', border: '1px solid #fca5a5', color: '#dc2626', borderRadius: 6, padding: '4px 12px', cursor: 'pointer', fontSize: 12 }}>
                          Revoke
                        </button>
                      )}
                    </td>
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
