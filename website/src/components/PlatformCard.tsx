import type { Platform } from '../data/platforms'

interface Props {
  platform: Platform
}

export default function PlatformCard({ platform }: Props) {
  return (
    <div className="glass-card" style={{ borderColor: `${platform.color}22` }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
        <div style={{
          width: 10, height: 10, borderRadius: '50%',
          background: platform.color,
          boxShadow: `0 0 8px ${platform.color}`,
        }} />
        <h3 style={{ fontSize: '1.25rem', fontWeight: 600 }}>{platform.name}</h3>
        <span className={`badge ${platform.status === 'active' ? 'badge-active' : 'badge-planned'}`}>
          {platform.status}
        </span>
      </div>
      <p style={{ color: '#94a3b8', fontSize: '0.9rem', lineHeight: 1.6, marginBottom: '1rem' }}>
        {platform.description}
      </p>
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
        {platform.stack.map(t => <span key={t} className="tech-tag">{t}</span>)}
        <span className="tech-tag" style={{ opacity: 0.6 }}>{platform.licence}</span>
      </div>
    </div>
  )
}
