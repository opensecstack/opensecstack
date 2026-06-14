import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { listUsers, deactivateUser } from '@/api/admin'
import Layout from '@/components/Layout'
import PageHeader from '@/components/PageHeader'
import Card from '@/components/Card'
import { UserX } from 'lucide-react'

const th: React.CSSProperties = { textAlign: 'left', padding: '12px 16px', fontSize: 13, fontWeight: 600, color: '#6b7280', background: '#f9fafb', borderBottom: '1px solid #e5e7eb' }
const td: React.CSSProperties = { padding: '12px 16px', fontSize: 14, borderBottom: '1px solid #f3f4f6' }

export default function Users() {
  const qc = useQueryClient()
  const { data, isLoading } = useQuery({ queryKey: ['users'], queryFn: () => listUsers() })
  const deactivate = useMutation({
    mutationFn: deactivateUser,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  })

  return (
    <Layout>
      <PageHeader title="Users" description="Manage sinauth user accounts" />
      <Card>
        {isLoading ? (
          <div style={{ padding: 48, textAlign: 'center', color: '#9ca3af' }}>Loading…</div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                {['Username', 'Email', 'Role', 'Created', 'Actions'].map(h => <th key={h} style={th}>{h}</th>)}
              </tr>
            </thead>
            <tbody>
              {((data as { users?: Array<{ id: string; username: string; email?: string; role: string; created_at: string; deactivated_at?: string }> })?.users || []).map(u => (
                <tr key={u.id}>
                  <td style={{ ...td, fontWeight: 600 }}>{u.username}</td>
                  <td style={{ ...td, color: '#6b7280' }}>{u.email || '—'}</td>
                  <td style={td}>
                    <span style={{ padding: '2px 8px', borderRadius: 12, fontSize: 12, fontWeight: 600, background: '#eff2ff', color: '#2f4bc7' }}>{u.role}</span>
                  </td>
                  <td style={{ ...td, color: '#6b7280' }}>{new Date(u.created_at).toLocaleDateString()}</td>
                  <td style={td}>
                    {!u.deactivated_at && (
                      <button onClick={() => deactivate.mutate(u.id)}
                        title="Deactivate"
                        style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#ef4444', padding: 4 }}>
                        <UserX size={16} />
                      </button>
                    )}
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
