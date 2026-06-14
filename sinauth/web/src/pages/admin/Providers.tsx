import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { listProviders, createProvider, deleteProvider } from '@/api/admin'
import Layout from '@/components/Layout'
import PageHeader from '@/components/PageHeader'
import Card from '@/components/Card'
import { Plus, Trash2 } from 'lucide-react'

const inp: React.CSSProperties = { width: '100%', border: '1px solid #d1d5db', borderRadius: 8, padding: '8px 12px', fontSize: 14, outline: 'none', boxSizing: 'border-box' }
const th: React.CSSProperties = { textAlign: 'left', padding: '12px 16px', fontSize: 13, fontWeight: 600, color: '#6b7280', background: '#f9fafb', borderBottom: '1px solid #e5e7eb' }
const td: React.CSSProperties = { padding: '12px 16px', fontSize: 14, borderBottom: '1px solid #f3f4f6' }

type Provider = { id: string; name: string; slug: string; type: string; enabled: boolean }

export default function Providers() {
  const qc = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ name: '', slug: '', type: 'oidc', oidc_issuer: '', oidc_client_id: '', oidc_client_secret: '', ldap_url: '', ldap_bind_dn: '', ldap_bind_password: '', ldap_base_dn: '', default_role: 'viewer' })

  const { data, isLoading } = useQuery({ queryKey: ['providers'], queryFn: listProviders })
  const create = useMutation({
    mutationFn: () => createProvider(form as Record<string, unknown>),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['providers'] }); setShowForm(false) },
  })
  const remove = useMutation({
    mutationFn: deleteProvider,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['providers'] }),
  })

  return (
    <Layout>
      <PageHeader
        title="Identity Providers"
        description="Federation: Azure AD, LDAP/Active Directory, SAML"
        action={
          <button onClick={() => setShowForm(true)}
            style={{ display: 'flex', alignItems: 'center', gap: 8, background: '#2f4bc7', color: 'white', border: 'none', borderRadius: 8, padding: '8px 16px', fontSize: 14, cursor: 'pointer' }}>
            <Plus size={16} /> Add Provider
          </button>
        }
      />
      {showForm && (
        <Card style={{ padding: 24, marginBottom: 24 }}>
          <h3 style={{ margin: '0 0 16px', fontSize: 16, fontWeight: 600 }}>Add Identity Provider</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16, marginBottom: 16 }}>
            <div>
              <label style={{ display: 'block', fontSize: 14, fontWeight: 500, marginBottom: 4 }}>Type</label>
              <select style={inp} value={form.type} onChange={e => setForm(f => ({ ...f, type: e.target.value }))}>
                {['oidc', 'saml', 'ldap'].map(t => <option key={t} value={t}>{t.toUpperCase()}</option>)}
              </select>
            </div>
            <div>
              <label style={{ display: 'block', fontSize: 14, fontWeight: 500, marginBottom: 4 }}>Display Name</label>
              <input style={inp} value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: 14, fontWeight: 500, marginBottom: 4 }}>Slug</label>
              <input style={inp} value={form.slug} placeholder="e.g. akshi-azure" onChange={e => setForm(f => ({ ...f, slug: e.target.value }))} />
            </div>
            {form.type === 'oidc' && <>
              <div style={{ gridColumn: '1 / -1' }}>
                <label style={{ display: 'block', fontSize: 14, fontWeight: 500, marginBottom: 4 }}>Issuer URL</label>
                <input style={inp} value={form.oidc_issuer} placeholder="https://login.microsoftonline.com/{tenant}/v2.0"
                  onChange={e => setForm(f => ({ ...f, oidc_issuer: e.target.value }))} />
              </div>
              <div>
                <label style={{ display: 'block', fontSize: 14, fontWeight: 500, marginBottom: 4 }}>Client ID</label>
                <input style={inp} value={form.oidc_client_id} onChange={e => setForm(f => ({ ...f, oidc_client_id: e.target.value }))} />
              </div>
              <div>
                <label style={{ display: 'block', fontSize: 14, fontWeight: 500, marginBottom: 4 }}>Client Secret</label>
                <input style={inp} type="password" value={form.oidc_client_secret} onChange={e => setForm(f => ({ ...f, oidc_client_secret: e.target.value }))} />
              </div>
            </>}
            {form.type === 'ldap' && <>
              <div>
                <label style={{ display: 'block', fontSize: 14, fontWeight: 500, marginBottom: 4 }}>LDAP URL</label>
                <input style={inp} value={form.ldap_url} placeholder="ldap://dc.example.com:389" onChange={e => setForm(f => ({ ...f, ldap_url: e.target.value }))} />
              </div>
              <div>
                <label style={{ display: 'block', fontSize: 14, fontWeight: 500, marginBottom: 4 }}>Bind DN</label>
                <input style={inp} value={form.ldap_bind_dn} onChange={e => setForm(f => ({ ...f, ldap_bind_dn: e.target.value }))} />
              </div>
              <div>
                <label style={{ display: 'block', fontSize: 14, fontWeight: 500, marginBottom: 4 }}>Base DN</label>
                <input style={inp} value={form.ldap_base_dn} onChange={e => setForm(f => ({ ...f, ldap_base_dn: e.target.value }))} />
              </div>
            </>}
            <div>
              <label style={{ display: 'block', fontSize: 14, fontWeight: 500, marginBottom: 4 }}>Default Role</label>
              <input style={inp} value={form.default_role} onChange={e => setForm(f => ({ ...f, default_role: e.target.value }))} />
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={() => create.mutate()}
              style={{ background: '#2f4bc7', color: 'white', border: 'none', borderRadius: 8, padding: '8px 16px', fontSize: 14, cursor: 'pointer' }}>Add</button>
            <button onClick={() => setShowForm(false)}
              style={{ border: '1px solid #d1d5db', background: 'white', borderRadius: 8, padding: '8px 16px', fontSize: 14, cursor: 'pointer' }}>Cancel</button>
          </div>
        </Card>
      )}
      <Card>
        {isLoading ? <div style={{ padding: 48, textAlign: 'center', color: '#9ca3af' }}>Loading…</div> : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead><tr>{['Name', 'Type', 'Slug', 'Status', 'Actions'].map(h => <th key={h} style={th}>{h}</th>)}</tr></thead>
            <tbody>
              {((data as Provider[]) || []).map(p => (
                <tr key={p.id}>
                  <td style={{ ...td, fontWeight: 600 }}>{p.name}</td>
                  <td style={td}><span style={{ padding: '2px 8px', background: '#f3f4f6', borderRadius: 4, fontFamily: 'monospace', fontSize: 12 }}>{p.type}</span></td>
                  <td style={{ ...td, fontFamily: 'monospace', fontSize: 12, color: '#6b7280' }}>{p.slug}</td>
                  <td style={td}>
                    <span style={{ padding: '2px 8px', borderRadius: 12, fontSize: 12, fontWeight: 600, background: p.enabled ? '#dcfce7' : '#f3f4f6', color: p.enabled ? '#16a34a' : '#6b7280' }}>
                      {p.enabled ? 'Active' : 'Disabled'}
                    </span>
                  </td>
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
