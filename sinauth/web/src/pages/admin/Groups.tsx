import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { listGroups, createGroup, deleteGroup } from '@/api/admin'
import Layout from '@/components/Layout'
import PageHeader from '@/components/PageHeader'
import Card from '@/components/Card'
import { Plus, Trash2 } from 'lucide-react'

const inp: React.CSSProperties = { width: '100%', border: '1px solid #d1d5db', borderRadius: 8, padding: '8px 12px', fontSize: 14, outline: 'none', boxSizing: 'border-box' }
const th: React.CSSProperties = { textAlign: 'left', padding: '12px 16px', fontSize: 13, fontWeight: 600, color: '#6b7280', background: '#f9fafb', borderBottom: '1px solid #e5e7eb' }
const td: React.CSSProperties = { padding: '12px 16px', fontSize: 14, borderBottom: '1px solid #f3f4f6' }

type Group = { id: string; name: string; description: string; created_at: string }

export default function Groups() {
  const qc = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ name: '', description: '' })

  const { data, isLoading } = useQuery({ queryKey: ['groups'], queryFn: listGroups })
  const create = useMutation({
    mutationFn: () => createGroup(form.name, form.description),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['groups'] }); setShowForm(false); setForm({ name: '', description: '' }) },
  })
  const remove = useMutation({
    mutationFn: deleteGroup,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['groups'] }),
  })

  return (
    <Layout>
      <PageHeader
        title="Groups"
        description="Organize users and assign roles collectively"
        action={
          <button onClick={() => setShowForm(true)}
            style={{ display: 'flex', alignItems: 'center', gap: 8, background: '#2f4bc7', color: 'white', border: 'none', borderRadius: 8, padding: '8px 16px', fontSize: 14, cursor: 'pointer' }}>
            <Plus size={16} /> New Group
          </button>
        }
      />
      {showForm && (
        <Card style={{ padding: 24, marginBottom: 24 }}>
          <h3 style={{ margin: '0 0 16px', fontSize: 16, fontWeight: 600 }}>Create Group</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
            <div>
              <label style={{ display: 'block', fontSize: 14, fontWeight: 500, marginBottom: 4 }}>Name</label>
              <input style={inp} value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: 14, fontWeight: 500, marginBottom: 4 }}>Description</label>
              <input style={inp} value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
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
            <thead><tr>{['Name', 'Description', 'Created', 'Actions'].map(h => <th key={h} style={th}>{h}</th>)}</tr></thead>
            <tbody>
              {((data as Group[]) || []).map(g => (
                <tr key={g.id}>
                  <td style={{ ...td, fontWeight: 600 }}>{g.name}</td>
                  <td style={{ ...td, color: '#6b7280' }}>{g.description || '—'}</td>
                  <td style={{ ...td, color: '#6b7280' }}>{new Date(g.created_at).toLocaleDateString()}</td>
                  <td style={td}>
                    <button onClick={() => remove.mutate(g.id)}
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
