import { motion } from 'framer-motion'
import ScrollSection from '../components/ScrollSection'

const phases = [
  { n: 1, title: 'Ecosystem v1.0.0',          status: 'done',  items: ['11 platforms + SDK', 'CITADEL governance layer', '4-language SDK (Go · Python · TypeScript · Rust)', 'All platforms Apache 2.0 / AGPL-3.0'] },
  { n: 2, title: 'v1.1 — Security Hardening', status: 'next',  items: ['JWKS endpoint', 'mTLS between platforms', 'PQ algorithm-identifier fields', 'Third-party security audit'] },
  { n: 3, title: 'v2.0 — Post-Quantum',       status: 'plan',  items: ['Hybrid Ed25519 + ML-DSA signatures', 'VIGIL ecosystem health monitor', 'QuintHash (PQ-resistant primitives)'] },
  { n: 4, title: 'v3.0 — Sovereignty Stack',  status: 'plan',  items: ['ML-DSA default (aligned with NIS3)', 'vantage-hash extracted library', 'Phase 5 Tier A governance tooling'] },
]

export default function RoadmapSection() {
  return (
    <ScrollSection id="roadmap">
      <h2 className="section-title"><span className="gradient-text">Roadmap</span></h2>
      <p className="section-subtitle">From the shipped v1.0 ecosystem to the post-quantum, sovereignty-focused v3.0 roadmap.</p>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        {phases.map((p, i) => {
          const isDone = p.status === 'done'
          const isNext = p.status === 'next'
          const borderColor = isDone ? '#10b981' : isNext ? '#00f0ff' : '#334155'
          return (
            <motion.div
              key={p.n}
              className="glass-card"
              initial={{ opacity: 0, x: -40 }}
              whileInView={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.1, duration: 0.5, ease: [0.25, 0.1, 0.25, 1] }}
              viewport={{ once: true }}
              style={{
                borderLeft: `3px solid ${borderColor}`,
                boxShadow: isNext ? '0 0 20px rgba(0,240,255,0.06)' : 'none',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '0.5rem' }}>
                <span style={{
                  fontFamily: 'var(--mono)', fontSize: '0.8rem', fontWeight: 700,
                  color: isDone ? '#34d399' : '#00f0ff',
                  textShadow: isDone ? '0 0 8px rgba(52,211,153,0.3)' : '0 0 8px rgba(0,240,255,0.3)',
                }}>
                  Phase {p.n}
                </span>
                <span style={{ fontWeight: 700, fontSize: '1.05rem' }}>{p.title}</span>
                <span className={`badge ${isDone ? 'badge-active' : isNext ? 'badge-planned' : 'badge-planned'}`}>
                  {isDone ? 'Completed' : isNext ? 'Next' : 'Planned'}
                </span>
              </div>
              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                {p.items.map(item => <span key={item} className="tech-tag">{item}</span>)}
              </div>
            </motion.div>
          )
        })}
      </div>
    </ScrollSection>
  )
}
