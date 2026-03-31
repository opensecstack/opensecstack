import { motion } from 'framer-motion'
import ScrollSection from '../components/ScrollSection'

const phases = [
  { n: 1, title: 'Foundation',              status: 'done',    items: ['APIGuard v0.1', 'CITADEL core', 'Go + Python SDKs'] },
  { n: 2, title: 'Full OWASP + CI/CD',     status: 'done',    items: ['10/10 OWASP modules', 'Ecosystem CI pipeline', 'Security scanning'] },
  { n: 3, title: 'Dashboard + Multi-tenant', status: 'done',   items: ['NIS2 Compass MVP', 'React frontends', 'Report generation'] },
  { n: 4, title: 'Governance Integration',  status: 'done',    items: ['MARSHAL 5-gate', 'WORM chain', 'SDK parity (Go/Py/Rust)', 'vantage-hash'] },
  { n: 5, title: 'Production + Ecosystem',  status: 'next',    items: ['v1.0.0 audit', 'IRFlow', 'ThreatFlow', 'OpenScrub', 'CyberPath'] },
]

export default function RoadmapSection() {
  return (
    <ScrollSection id="roadmap">
      <h2 className="section-title"><span className="gradient-text">Roadmap</span></h2>
      <p className="section-subtitle">Where we are and where we're heading.</p>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        {phases.map((p, i) => (
          <motion.div
            key={p.n}
            className="glass-card"
            initial={{ opacity: 0, x: -30 }}
            whileInView={{ opacity: 1, x: 0 }}
            transition={{ delay: i * 0.1, duration: 0.4 }}
            viewport={{ once: true }}
            style={{ borderLeft: `3px solid ${p.status === 'done' ? '#10b981' : p.status === 'next' ? '#00f0ff' : '#334155'}` }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '0.5rem' }}>
              <span style={{
                fontFamily: 'var(--mono)', fontSize: '0.8rem', fontWeight: 700,
                color: p.status === 'done' ? '#10b981' : '#00f0ff',
              }}>
                Phase {p.n}
              </span>
              <span style={{ fontWeight: 600, fontSize: '1.05rem' }}>{p.title}</span>
              <span className={`badge ${p.status === 'done' ? 'badge-active' : 'badge-planned'}`}>
                {p.status === 'done' ? 'Completed' : 'Next'}
              </span>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
              {p.items.map(item => <span key={item} className="tech-tag">{item}</span>)}
            </div>
          </motion.div>
        ))}
      </div>
    </ScrollSection>
  )
}
