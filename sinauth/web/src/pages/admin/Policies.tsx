import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { listPolicies, createPolicy, deletePolicy } from '@/api/admin'
import Layout from '@/components/Layout'
import PageHeader from '@/components/PageHeader'
import Card from '@/components/Card'
import { Plus, Trash2 } from 'lucide-react'

const inp: React.CSSProperties = { width: '100%', border: '1px solid #d1d5db', borderRadius: 8, padding: '8px 12px', fontSize: 14, outline: 'none', boxSizing: 'border-box' }
const th: React.CSSProperties = { textAlign: 'left', padding: '12px 16px', fontSize: 13, fontWeight: 600, color: '#6b7280', background: '#f9fafb', borderBottom: '1px solid #e5e7eb' }
const td: React.CSSProperties = { padding: '12px 16px', fontSize: 14, borderBottom: '1px solid #f3f4f6' }

type Policy = { id: string; name: string; type: string; client_id?: string; role_name?: string; enabled: boolean }

const POLICY_TYPES = ['require_mfa', 'require_email_verified', 'deny_role', 'allow_client']

export default function Policies() {
  const qc = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ name: '', description: '', type: 'require_mfa', client_id: '', role_name: '' })

  const { data, isLoading } = useQuery({ queryKey: ['policies'], queryFn: listPolicies })
  const create = useMutation({
    mutationFn: () => createPolicy(form as Record<string, unknown>),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['policies'] }); setShowForm(false) },
  })
  const remove = useMutation({
    mutationFn: deletePolicy,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['policies'] }),
  })

  return (
    <Layout>
      <PageHeader
        title="Policies"
        description="Rules evaluated at token issuance — MFA, email verification, role restrictions"
        action={
          <button onClick={() => setShowForm(true)}
            style={{ display: 'flex', alignItems: 'center', gap: 8, background: '#2f4bc7', color: 'white', border: 'none', borderRadius: 8, padding: '8px 16px', fontSize: 14, cursor: 'pointer' }}>
            <Plus size={16} /> New Policy
          </button>
        }
      />
      {showForm && (
        <Card style={{ padding: 24, marginBottom: 24 }}>
          <h3 style={{ margin: '0 0 16px', fontSize: 16, fontWeight: 600 }}>Create Policy</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
            <div>
              <label style={{ display: 'block', fontSize: 14, fontWeight: 500, marginBottom: 4 }}>Name</label>
              <input style={inp} value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: 14, fontWeight: 500, marginBottom: 4 }}>Type</label>
              <select style={inp} value={form.type} onChange={e => setForm(f => ({ ...f, type: e.target.value }))}>
                {POLICY_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>
            <div>
              <label style={{ display: 'block', fontSize: 14, fontWeight: 500, marginBottom: 4 }}>Client ID <span style={{ color: '#9ca3af', fontWeight: 400 }}>(optional — empty = all clients)</span></label>
              <input style={inp} value={form.client_id} placeholder="community"
                onChange={e => setForm(f => ({ ...f, client_id: e.target.value }))} />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: 14, fontWeight: 500, marginBottom: 4 }}>Role Name <span style={{ color: '#9ca3af', fontWeight: 400 }}>(optional — empty = all roles)</span></label>
              <input style={inp} value={form.role_name} placeholder="admin"
                onChange={e => setForm(f => ({ ...f, role_name: e.target.value }))} />
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={() => create.mutate()}
              style={{ background: '#2f4bc7', color: 'white', border: 'none', borderRadius: 8, padding: '8px 16px', fontSize: 14, cursor: 'pointer' }}>Create</button>
            <button onClick={() => setShowForm(false)}
              style={{ border: '1px solid #d1d5db', background: 'white', borderRadius: 8, padding: '8px 16px', fontSize: 14, cursor: 'pointer' }}>Cancel</button>
          </div>
        </Card>
      )}
      <Card>
        {isLoading ? <div style={{ padding: 48, textAlign: 'center', color: '#9ca3af' }}>Loading…</div> : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead><tr>{['Name', 'Type', 'Client', 'Role', 'Actions'].map(h => <th key={h} style={th}>{h}</th>)}</tr></thead>
            <tbody>
              {((data as Policy[]) || []).map(p => (
                <tr key={p.id}>
                  <td style={{ ...td, fontWeight: 600 }}>{p.name}</td>
                  <td style={td}>
                    <span style={{ padding: '2px 8px', background: '#eff6ff', color: '#1d4ed8', borderRadius: 4, fontFamily: 'monospace', fontSize: 12 }}>{p.type}</span>
                  </td>
                  <td style={{ ...td, color: '#6b7280' }}>{p.client_id || 'All'}</td>
                  <td style={{ ...td, color: '#6b7280' }}>{p.role_name || 'All'}</td>
                  <td style={td}>
                    <button onClick={() => remove.mutate(p.id)}
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
