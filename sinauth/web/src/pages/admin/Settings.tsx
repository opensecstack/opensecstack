import { useQuery } from '@tanstack/react-query'
import axios from 'axios'
import Layout from '../../components/Layout'
import PageHeader from '../../components/PageHeader'
import Card from '../../components/Card'

const th: React.CSSProperties = { textAlign: 'left', padding: '12px 16px', fontSize: 13, fontWeight: 600, color: '#6b7280', background: '#f9fafb', borderBottom: '1px solid #e5e7eb' }
const td: React.CSSProperties = { padding: '12px 16px', fontSize: 14, borderBottom: '1px solid #f3f4f6' }
const labelStyle: React.CSSProperties = { fontSize: 13, fontWeight: 600, color: '#6b7280', marginBottom: 4, display: 'block' }
const valueStyle: React.CSSProperties = { fontFamily: 'monospace', fontSize: 13, color: '#111827', background: '#f9fafb', padding: '6px 10px', borderRadius: 6, border: '1px solid #e5e7eb', display: 'block', wordBreak: 'break-all' }

type OIDCConfig = {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  jwks_uri: string
}

const ENDPOINTS = [
  { method: 'GET',  path: '/oauth/authorize',             description: 'Authorization endpoint' },
  { method: 'POST', path: '/oauth/token',                 description: 'Token endpoint' },
  { method: 'GET',  path: '/oauth/userinfo',              description: 'UserInfo endpoint' },
  { method: 'POST', path: '/oauth/endsession',            description: 'End session / logout' },
  { method: 'POST', path: '/api/v1/auth/register',        description: 'User registration' },
  { method: 'POST', path: '/api/v1/auth/login',           description: 'User login' },
  { method: 'POST', path: '/api/v1/auth/forgot-password', description: 'Initiate password reset' },
  { method: 'POST', path: '/api/v1/auth/reset-password',  description: 'Complete password reset' },
]

const METHOD_COLORS: Record<string, React.CSSProperties> = {
  GET:  { background: '#eff6ff', color: '#1d4ed8' },
  POST: { background: '#f0fdf4', color: '#15803d' },
}

export default function Settings() {
  const { data: oidc, isLoading } = useQuery<OIDCConfig>({
    queryKey: ['oidc-config'],
    queryFn: () => axios.get<OIDCConfig>('/.well-known/openid-configuration').then(r => r.data),
  })

  return (
    <Layout>
      <PageHeader
        title="Settings"
        description="System configuration and endpoint reference"
      />

      {/* System Information */}
      <Card style={{ marginBottom: 24 }}>
        <div style={{ padding: '16px 20px', borderBottom: '1px solid #e5e7eb' }}>
          <h2 style={{ margin: 0, fontSize: 16, fontWeight: 600, color: '#111827' }}>System Information</h2>
          <p style={{ margin: '4px 0 0', fontSize: 14, color: '#6b7280' }}>Live data from the OpenID Connect discovery document</p>
        </div>
        <div style={{ padding: 20 }}>
          {isLoading ? (
            <div style={{ padding: 24, textAlign: 'center', color: '#9ca3af' }}>Loading…</div>
          ) : oidc ? (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              {[
                { label: 'Issuer',                  value: oidc.issuer },
                { label: 'Authorization Endpoint',  value: oidc.authorization_endpoint },
                { label: 'Token Endpoint',           value: oidc.token_endpoint },
                { label: 'JWKS URI',                 value: oidc.jwks_uri },
              ].map(({ label, value }) => (
                <div key={label}>
                  <span style={labelStyle}>{label}</span>
                  <span style={valueStyle}>{value}</span>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ color: '#ef4444', fontSize: 14 }}>Failed to load discovery document.</div>
          )}
        </div>
      </Card>

      {/* API Endpoints */}
      <Card style={{ marginBottom: 24 }}>
        <div style={{ padding: '16px 20px', borderBottom: '1px solid #e5e7eb' }}>
          <h2 style={{ margin: 0, fontSize: 16, fontWeight: 600, color: '#111827' }}>API Endpoints</h2>
          <p style={{ margin: '4px 0 0', fontSize: 14, color: '#6b7280' }}>Reference for all available HTTP endpoints</p>
        </div>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              {['Method', 'Path', 'Description'].map(h => <th key={h} style={th}>{h}</th>)}
            </tr>
          </thead>
          <tbody>
            {ENDPOINTS.map(({ method, path, description }) => (
              <tr key={path}>
                <td style={td}>
                  <span style={{ ...METHOD_COLORS[method], padding: '2px 8px', borderRadius: 4, fontFamily: 'monospace', fontSize: 12, fontWeight: 600 }}>
                    {method}
                  </span>
                </td>
                <td style={{ ...td, fontFamily: 'monospace', fontSize: 13 }}>{path}</td>
                <td style={{ ...td, color: '#6b7280' }}>{description}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      {/* Security */}
      <Card>
        <div style={{ padding: '16px 20px', borderBottom: '1px solid #e5e7eb' }}>
          <h2 style={{ margin: 0, fontSize: 16, fontWeight: 600, color: '#111827' }}>Security</h2>
          <p style={{ margin: '4px 0 0', fontSize: 14, color: '#6b7280' }}>Security policies and configuration</p>
        </div>
        <div style={{ padding: 20, display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>
          <div style={{ background: '#f9fafb', border: '1px solid #e5e7eb', borderRadius: 8, padding: 16 }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: '#6b7280', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>Rate Limits</div>
            <div style={{ fontSize: 14, color: '#111827', lineHeight: 1.6 }}>
              <div>5 req/min on auth endpoints</div>
              <div>120 req/min global</div>
            </div>
          </div>
          <div style={{ background: '#f9fafb', border: '1px solid #e5e7eb', borderRadius: 8, padding: 16 }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: '#6b7280', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>Token Format</div>
            <div style={{ fontSize: 14, color: '#111827', lineHeight: 1.6 }}>
              <div>RS256 signed JWT</div>
            </div>
          </div>
          <div style={{ background: '#f9fafb', border: '1px solid #e5e7eb', borderRadius: 8, padding: 16 }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: '#6b7280', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>MFA Methods</div>
            <div style={{ fontSize: 14, color: '#111827', lineHeight: 1.6 }}>
              <div>TOTP</div>
              <div>SMS (Twilio)</div>
              <div>FIDO2 / WebAuthn / Passkey</div>
            </div>
          </div>
        </div>
      </Card>
    </Layout>
  )
}
