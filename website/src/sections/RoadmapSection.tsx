import { motion } from 'framer-motion'
import { Link } from 'react-router-dom'
import ScrollSection, { SECTION_EASE, SECTION_VIEWPORT_MARGIN } from '../components/ScrollSection'

const MAX_STAGGER_INDEX = 6

const phases = [
  { n: 1, title: 'v1.0.0 → v1.2.0 — Full Ecosystem', status: 'done', items: ['12 platforms + SDK', 'CITADEL governance layer', '4-language SDK (Go · Python · TypeScript · Rust)', 'All platforms Apache 2.0 / AGPL-3.0'] },
  { n: 2, title: 'v2.0.0 — Post-Quantum',     status: 'next', items: ['Hybrid Ed25519 + ML-DSA signatures', 'SHA-256 → quintHash migration', 'AI governance — MARSHAL gate for AI-initiated actions'] },
  { n: 3, title: 'v2.5.0 — Sovereignty Tooling', status: 'plan', items: ['vantage-hash standalone crate', 'pyramid-registry v1.0 — DAG + W3C DID + FROST', 'Runix alpha — kernel, capability manager, Wasm already live'] },
  { n: 4, title: 'v3.0.0 — NIS3-Ready Bundle', status: 'plan',  items: ['NIS3 adoption alignment (2030-2032)', 'Ecosystem-wide compliance mapping refresh'] },
]

export default function RoadmapSection() {
  return (
    <ScrollSection id="roadmap">
      <h2 className="section-title"><span className="gradient-text">Roadmap</span></h2>
      <p className="section-subtitle">From the shipped, full-platform v1.2 ecosystem to the post-quantum, sovereignty-focused v3.0 roadmap.</p>
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
              transition={{ delay: Math.min(i, MAX_STAGGER_INDEX) * 0.1, duration: 0.5, ease: SECTION_EASE }}
              viewport={{ once: true, margin: SECTION_VIEWPORT_MARGIN }}
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

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        whileInView={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, ease: SECTION_EASE }}
        viewport={{ once: true, margin: SECTION_VIEWPORT_MARGIN }}
        style={{
          marginTop: '2.5rem', textAlign: 'center', display: 'flex',
          flexDirection: 'column', alignItems: 'center', gap: '1.25rem',
        }}
      >
        <h3 style={{ fontSize: '1.3rem', fontWeight: 700 }}>Follow the build</h3>
        <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', justifyContent: 'center' }}>
          <a href="https://github.com/opensecstack/opensecstack" target="_blank" rel="noopener noreferrer" style={{
            padding: '13px 30px', borderRadius: 11, fontWeight: 700, fontSize: '0.95rem',
            background: 'linear-gradient(135deg, #00f0ff, #7c3aed)', color: '#030308',
            textDecoration: 'none', boxShadow: '0 0 30px rgba(0,240,255,0.2)',
            transition: 'box-shadow 0.3s',
          }}>
            Star on GitHub
          </a>
          <Link to="/docs/releases" style={{
            padding: '13px 30px', borderRadius: 11, fontWeight: 600, fontSize: '0.95rem',
            border: '1px solid rgba(0,240,255,0.25)', color: 'var(--accent)',
            textDecoration: 'none', backdropFilter: 'blur(8px)',
            transition: 'border-color 0.3s, box-shadow 0.3s',
          }}>
            Watch for Releases
          </Link>
        </div>
      </motion.div>
    </ScrollSection>
  )
}
