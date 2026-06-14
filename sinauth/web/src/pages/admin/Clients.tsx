import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { listClients, createClient, deleteClient } from '@/api/admin'
import Layout from '@/components/Layout'
import PageHeader from '@/components/PageHeader'
import Card from '@/components/Card'
import { Plus, Trash2, Copy } from 'lucide-react'

const inp: React.CSSProperties = { width: '100%', border: '1px solid #d1d5db', borderRadius: 8, padding: '8px 12px', fontSize: 14, outline: 'none', boxSizing: 'border-box' }
const th: React.CSSProperties = { textAlign: 'left', padding: '12px 16px', fontSize: 13, fontWeight: 600, color: '#6b7280', background: '#f9fafb', borderBottom: '1px solid #e5e7eb' }
const td: React.CSSProperties = { padding: '12px 16px', fontSize: 14, borderBottom: '1px solid #f3f4f6' }

type Client = { id: string; client_id: string; name?: string; grant_types?: string[] }

export default function Clients() {
  const qc = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ client_id: '', name: '', redirect_uris: '', grant_types: 'authorization_code', scopes: 'openid profile email' })

  const { data, isLoading } = useQuery({ queryKey: ['clients'], queryFn: listClients })
  const create = useMutation({
    mutationFn: () => createClient({ ...form, redirect_uris: form.redirect_uris.split('\n').map(s => s.trim()).filter(Boolean) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['clients'] }); setShowForm(false) },
  })
  const remove = useMutation({
    mutationFn: deleteClient,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['clients'] }),
  })

  return (
    <Layout>
      <PageHeader
        title="Applications"
        description="OAuth2 clients that use sinauth for authentication"
        action={
          <button onClick={() => setShowForm(true)}
            style={{ display: 'flex', alignItems: 'center', gap: 8, background: '#2f4bc7', color: 'white', border: 'none', borderRadius: 8, padding: '8px 16px', fontSize: 14, cursor: 'pointer' }}>
            <Plus size={16} /> New Application
          </button>
        }
      />
      {showForm && (
        <Card style={{ padding: 24, marginBottom: 24 }}>
          <h3 style={{ margin: '0 0 16px', fontSize: 16, fontWeight: 600 }}>Register Application</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
            <div>
              <label style={{ display: 'block', fontSize: 14, fontWeight: 500, marginBottom: 4 }}>Client ID</label>
              <input style={inp} value={form.client_id} placeholder="e.g. community"
                onChange={e => setForm(f => ({ ...f, client_id: e.target.value }))} />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: 14, fontWeight: 500, marginBottom: 4 }}>Display Name</label>
              <input style={inp} value={form.name} placeholder="e.g. SIN Community"
                onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
            </div>
            <div style={{ gridColumn: '1 / -1' }}>
              <label style={{ display: 'block', fontSize: 14, fontWeight: 500, marginBottom: 4 }}>Redirect URIs (one per line)</label>
              <textarea style={{ ...inp, fontFamily: 'monospace' }} rows={3}
                value={form.redirect_uris} placeholder="https://community.sin.to/auth/callback"
                onChange={e => setForm(f => ({ ...f, redirect_uris: e.target.value }))} />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: 14, fontWeight: 500, marginBottom: 4 }}>Scopes</label>
              <input style={inp} value={form.scopes}
                onChange={e => setForm(f => ({ ...f, scopes: e.target.value }))} />
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={() => create.mutate()}
              style={{ background: '#2f4bc7', color: 'white', border: 'none', borderRadius: 8, padding: '8px 16px', fontSize: 14, cursor: 'pointer' }}>Register</button>
            <button onClick={() => setShowForm(false)}
              style={{ border: '1px solid #d1d5db', background: 'white', borderRadius: 8, padding: '8px 16px', fontSize: 14, cursor: 'pointer' }}>Cancel</button>
          </div>
        </Card>
      )}
      <Card>
        {isLoading ? <div style={{ padding: 48, textAlign: 'center', color: '#9ca3af' }}>Loading…</div> : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead><tr>{['Client ID', 'Name', 'Grant Types', 'Actions'].map(h => <th key={h} style={th}>{h}</th>)}</tr></thead>
            <tbody>
              {((data as Client[]) || []).map(c => (
                <tr key={c.id}>
                  <td style={td}>
                    <span style={{ display: 'flex', alignItems: 'center', gap: 8, fontFamily: 'monospace', fontSize: 12 }}>
                      {c.client_id}
                      <button onClick={() => navigator.clipboard.writeText(c.client_id)}
                        style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#9ca3af', padding: 2 }}>
                        <Copy size={12} />
                      </button>
                    </span>
                  </td>
                  <td style={td}>{c.name || '—'}</td>
                  <td style={{ ...td, color: '#6b7280' }}>{(c.grant_types || []).join(', ')}</td>
                  <td style={td}>
                    <button onClick={() => remove.mutate(c.id)}
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#ef4444', padding: 4 }}>
                      <Trash2 size={16} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </Layout>
  )
}
