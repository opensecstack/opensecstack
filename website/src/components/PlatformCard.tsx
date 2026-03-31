import { motion } from 'framer-motion'
import type { Platform } from '../data/platforms'

interface Props {
  platform: Platform
  index: number
}

export default function PlatformCard({ platform, index }: Props) {
  return (
    <motion.div
      className="glass-card"
      initial={{ opacity: 0, y: 30 }}
      whileInView={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.08, duration: 0.5 }}
      viewport={{ once: true }}
      style={{ borderColor: `${platform.color}18` }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
        <div style={{
          width: 10, height: 10, borderRadius: '50%',
          background: platform.color,
          boxShadow: `0 0 12px ${platform.color}88`,
        }} />
        <h3 style={{ fontSize: '1.2rem', fontWeight: 700 }}>{platform.name}</h3>
        <span className={`badge ${platform.status === 'active' ? 'badge-active' : 'badge-planned'}`}>
          {platform.status}
        </span>
      </div>
      <p style={{ color: '#8892a8', fontSize: '0.88rem', lineHeight: 1.65, marginBottom: '1rem' }}>
        {platform.description}
      </p>
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
        {platform.stack.map(t => <span key={t} className="tech-tag">{t}</span>)}
        <span className="tech-tag" style={{ opacity: 0.5 }}>{platform.licence}</span>
      </div>
    </motion.div>
  )
}
