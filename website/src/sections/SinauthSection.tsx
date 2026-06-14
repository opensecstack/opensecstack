import ScrollSection from '../components/ScrollSection'

const features = [
  'OAuth2 / OIDC Authorization Server',
  'PKCE flow for public clients',
  'TOTP two-factor authentication',
  'Triple-Hash WORM audit log',
  'RS256 JWT signed tokens',
  'Social login: Google & GitHub',
  'LDAP / SAML federation',
  'TypeScript & Go SDKs',
]

function SinauthLogo() {
  return (
    <svg width="44" height="44" viewBox="0 0 52 52" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect width="52" height="52" rx="14" fill="#1a2d7a"/>
      <circle cx="26" cy="16" r="9" fill="#0ea5e9"/>
      <circle cx="34.7" cy="31" r="9" fill="#6366f1"/>
      <circle cx="17.3" cy="31" r="9" fill="#6366f1"/>
      <circle cx="26" cy="26" r="6.5" fill="#1a2d7a"/>
      <circle cx="26" cy="16" r="3" fill="#1a2d7a"/>
      <circle cx="34.7" cy="31" r="3" fill="#1a2d7a"/>
      <circle cx="17.3" cy="31" r="3" fill="#1a2d7a"/>
    </svg>
  )
}

export default function SinauthSection() {
  return (
    <ScrollSection id="sinauth">
      <h2 className="section-title"><span className="gradient-text">sinauth</span></h2>
      <p className="section-subtitle">
        Everything identity — OAuth2 / OIDC identity provider powering every platform in the ecosystem.
        Triple-Hash WORM audit, RS256 JWT, PKCE, and federation built-in.
      </p>

      <div className="grid-2">
        {/* Login UI mockup */}
        <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '2rem' }}>
          <SinauthLogo />
          <div style={{ marginTop: '0.75rem', fontSize: '1.1rem', fontWeight: 700, color: '#e2e8f0' }}>
            sin<span style={{ color: '#6366f1' }}>auth</span>
          </div>

          {/* Tab bar */}
          <div style={{ display: 'flex', gap: 0, marginTop: '1.25rem', borderRadius: 8, overflow: 'hidden', border: '1px solid rgba(255,255,255,0.08)' }}>
            {['Sign In', 'Register'].map((tab, i) => (
              <div key={tab} style={{
                padding: '6px 20px', fontSize: '0.8rem', fontWeight: 600,
                background: i === 0 ? '#6366f1' : 'transparent',
                color: i === 0 ? 'white' : '#8892a8',
                cursor: 'default',
              }}>{tab}</div>
            ))}
          </div>

          {/* Mock form fields */}
          <div style={{ width: '100%', marginTop: '1rem', display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
            {['Email address', 'Password'].map(f => (
              <div key={f} style={{
                padding: '9px 12px', borderRadius: 7,
                border: '1px solid rgba(255,255,255,0.1)',
                background: 'rgba(255,255,255,0.03)',
                fontSize: '0.8rem', color: '#64748b',
              }}>{f}</div>
            ))}
            <div style={{
              padding: '9px 12px', borderRadius: 7,
              background: '#6366f1',
              fontSize: '0.8rem', fontWeight: 600, color: 'white', textAlign: 'center',
            }}>Sign In</div>
          </div>

          {/* Divider */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, width: '100%', marginTop: '0.75rem' }}>
            <div style={{ flex: 1, height: 1, background: 'rgba(255,255,255,0.08)' }} />
            <span style={{ fontSize: '0.7rem', color: '#64748b' }}>or continue with</span>
            <div style={{ flex: 1, height: 1, background: 'rgba(255,255,255,0.08)' }} />
          </div>

          {/* Social buttons */}
          <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.6rem', width: '100%' }}>
            {['Google', 'GitHub'].map(p => (
              <div key={p} style={{
                flex: 1, padding: '7px', borderRadius: 7, textAlign: 'center',
                border: '1px solid rgba(255,255,255,0.1)',
                background: 'rgba(255,255,255,0.03)',
                fontSize: '0.75rem', color: '#94a3b8',
              }}>● {p}</div>
            ))}
          </div>

          {/* Stats bar */}
          <div style={{
            marginTop: '1.25rem', display: 'flex', flexWrap: 'wrap', justifyContent: 'center',
            gap: '0.4rem 0.75rem', fontSize: '0.7rem', color: '#64748b',
          }}>
            {['13 Platforms', '4 SDKs', 'RS256 JWT', 'PKCE', 'Triple-Hash WORM Audit'].map((s, i, arr) => (
              <span key={s}>
                {s}{i < arr.length - 1 && <span style={{ margin: '0 0.2rem', color: '#334155' }}>·</span>}
              </span>
            ))}
          </div>
        </div>

        {/* Features */}
        <div className="glass-card">
          <h3 style={{ marginBottom: '1rem', fontSize: '1.1rem' }}>Capabilities</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
            {features.map(f => (
              <div key={f} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.85rem' }}>
                <span style={{ color: '#6366f1' }}>&#10003;</span> {f}
              </div>
            ))}
          </div>
          <div style={{ marginTop: '1.5rem', fontFamily: 'var(--mono)', fontSize: '0.78rem', color: '#94a3b8', lineHeight: 2 }}>
            <div><span className="tech-tag">API</span> Go — chi · pgx · zap</div>
            <div><span className="tech-tag">UI</span> React + TypeScript</div>
            <div><span className="tech-tag">Token</span> RS256 JWT · PKCE · TOTP</div>
            <div><span className="tech-tag">Audit</span> Triple-Hash WORM chain</div>
            <div><span className="tech-tag">Licence</span> Apache 2.0</div>
          </div>
        </div>
      </div>
    </ScrollSection>
  )
}
