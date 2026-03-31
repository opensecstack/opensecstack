import { lazy, Suspense } from 'react'
import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { mobileLayers, mvnoEvents, mvnoFeatures, mobilePhases } from '../data/citadelOSMobile'

const MobileScene = lazy(() => import('../scene/MobileScene'))

const fadeUp = {
  initial: { opacity: 0, y: 40 },
  whileInView: { opacity: 1, y: 0 },
  transition: { duration: 0.6, ease: [0.25, 0.1, 0.25, 1] },
  viewport: { once: true as const, margin: '-80px' },
}

export default function CitadelOSMobilePage() {
  return (
    <div style={{ background: 'var(--bg)', minHeight: '100vh' }}>
      <Suspense fallback={null}>
        <MobileScene />
      </Suspense>

      {/* Nav */}
      <nav style={{
        position: 'fixed', top: 0, left: 0, right: 0, zIndex: 100,
        background: 'rgba(3,3,8,0.7)', backdropFilter: 'blur(20px) saturate(150%)',
        borderBottom: '1px solid rgba(0,240,255,0.06)',
        padding: '0 2rem', height: 56, display: 'flex', alignItems: 'center', gap: '2rem',
      }}>
        <Link to="/" style={{
          fontWeight: 800, fontSize: '1.1rem',
          background: 'linear-gradient(135deg, #00f0ff, #7c3aed)',
          WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
          textDecoration: 'none',
        }}>
          SIN
        </Link>
        <span style={{ color: '#334155' }}>/</span>
        <Link to="/citadelos" style={{ color: '#8892a8', textDecoration: 'none', fontSize: '0.9rem' }}>CitadelOS</Link>
        <span style={{ color: '#334155' }}>/</span>
        <span style={{ color: '#10b981', fontWeight: 600, fontSize: '0.95rem' }}>Mobile + MVNO</span>
        <Link to="/" style={{ marginLeft: 'auto', color: '#8892a8', textDecoration: 'none', fontSize: '0.85rem' }}>
          Back to Ecosystem
        </Link>
      </nav>

      <div className="scroll-content" style={{ maxWidth: 1200, margin: '0 auto', padding: '0 2rem' }}>

        {/* Hero */}
        <section style={{ paddingTop: '12rem', paddingBottom: '6rem' }}>
          <motion.div initial={{ opacity: 0, y: 50 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.8 }}>
            <div style={{
              display: 'inline-block', padding: '5px 14px', borderRadius: 8, marginBottom: '1.5rem',
              background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.2)',
              fontSize: '0.8rem', fontFamily: 'var(--mono)', color: '#10b981', letterSpacing: '0.08em',
            }}>
              Phase 5 &middot; Mobile Alpha 2027 Q2
            </div>
            <h1 style={{
              fontSize: 'clamp(2.5rem, 6vw, 4.5rem)', fontWeight: 800,
              letterSpacing: '-0.04em', lineHeight: 1.05,
            }}>
              <span className="gradient-text">CitadelOS Mobile</span>
            </h1>
            <p style={{ fontSize: '1.4rem', color: '#e2e8f0', marginTop: '0.5rem', fontWeight: 500 }}>
              ARM TrustZone &middot; SIM Governance &middot; MVNO-Native
            </p>
            <p style={{ marginTop: '1.5rem', fontSize: '1.1rem', color: '#8892a8', lineHeight: 1.7, maxWidth: 620 }}>
              A mobile operating system where MVNO operations run natively on the microkernel stack.
              Every SIM activation, data policy change, and roaming agreement is a CITADEL governance event &mdash;
              auditable, immutable, NIS2-compliant.
            </p>

            <div className="stat-grid" style={{ marginTop: '2.5rem' }}>
              {[
                { v: '6', l: 'Mobile Layers' },
                { v: '5', l: 'MVNO Events' },
                { v: 'ARM', l: 'TrustZone' },
                { v: 'eSIM', l: 'Native' },
              ].map(s => (
                <div className="stat-item" key={s.l}>
                  <div className="stat-value">{s.v}</div>
                  <div className="stat-label">{s.l}</div>
                </div>
              ))}
            </div>

            <div style={{ marginTop: '2.5rem', display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
              <Link to="/citadelos" style={{
                padding: '12px 26px', borderRadius: 10, fontWeight: 600, fontSize: '0.9rem',
                border: '1px solid rgba(0,240,255,0.25)', color: '#00f0ff', textDecoration: 'none',
              }}>
                CitadelOS Desktop
              </Link>
            </div>
          </motion.div>
        </section>

        {/* 6 Mobile Layers */}
        <motion.section {...fadeUp} style={{ paddingBottom: '5rem' }}>
          <h2 className="section-title">Mobile OS &mdash; <span className="gradient-text">6 Layers + MVNO</span></h2>
          <p className="section-subtitle">
            From ARM TrustZone hardware to the secure dialer &mdash; every layer enforces isolation.
            MVNO operations run at L3 inside the microkernel stack.
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {mobileLayers.map((layer, i) => (
              <motion.div
                key={layer.number}
                className="glass-card"
                initial={{ opacity: 0, x: -40 }}
                whileInView={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.08, duration: 0.5 }}
                viewport={{ once: true }}
                style={{ borderLeft: `3px solid ${layer.color}` }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                  <div style={{
                    width: 40, height: 40, borderRadius: 8,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    background: `${layer.color}15`, border: `1px solid ${layer.color}30`,
                    fontFamily: 'var(--mono)', fontSize: '0.85rem', fontWeight: 700, color: layer.color,
                    flexShrink: 0,
                  }}>
                    {layer.code}
                  </div>
                  <div>
                    <div style={{ fontWeight: 700, fontSize: '1rem' }}>{layer.name}</div>
                    <div style={{ fontSize: '0.85rem', color: '#8892a8', marginTop: 2 }}>{layer.description}</div>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </motion.section>

        {/* MVNO Features */}
        <motion.section {...fadeUp} style={{ paddingBottom: '5rem' }}>
          <h2 className="section-title"><span className="gradient-text">MVNO</span> Integration</h2>
          <p className="section-subtitle">
            Mobile Virtual Network Operator: provides mobile services without owning spectrum.
            Every operation is a governance event &mdash; auditable under NIS2 Article 21.
          </p>
          <div className="grid-3">
            {mvnoFeatures.map(f => (
              <div key={f.title} className="glass-card">
                <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.75rem' }}>{f.title}</h3>
                <p style={{ color: '#8892a8', fontSize: '0.85rem', lineHeight: 1.65, marginBottom: '1rem' }}>
                  {f.description}
                </p>
                <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                  {f.tags.map(t => <span key={t} className="tech-tag">{t}</span>)}
                </div>
              </div>
            ))}
          </div>
        </motion.section>

        {/* MVNO Governance Flow */}
        <motion.section {...fadeUp} style={{ paddingBottom: '5rem' }}>
          <h2 className="section-title">Governance <span className="gradient-text">Operations Flow</span></h2>
          <p className="section-subtitle">
            Every MVNO operation passes through CITADEL MARSHAL gates.
            All outcomes are written to the immutable WORM chain.
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            {mvnoEvents.map((evt, i) => (
              <motion.div
                key={evt.name}
                className="glass-card"
                initial={{ opacity: 0, x: -30 }}
                whileInView={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.08, duration: 0.5 }}
                viewport={{ once: true }}
                style={{ borderLeft: `3px solid ${evt.color}` }}
              >
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1.25rem' }}>
                  <div style={{
                    minWidth: 120, padding: '6px 12px', borderRadius: 8,
                    background: `${evt.color}12`, border: `1px solid ${evt.color}25`,
                    textAlign: 'center',
                  }}>
                    <div style={{ fontWeight: 700, fontSize: '0.9rem', color: evt.color }}>{evt.name}</div>
                    <div style={{ fontSize: '0.7rem', fontFamily: 'var(--mono)', color: '#8892a8', marginTop: 2 }}>{evt.gates}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: '0.88rem', color: '#8892a8', lineHeight: 1.6 }}>{evt.flow}</div>
                    <div style={{ fontSize: '0.85rem', color: '#e2e8f0', marginTop: 4, fontWeight: 500 }}>
                      &rarr; {evt.outcome}
                    </div>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </motion.section>

        {/* ARM TrustZone + Hardware */}
        <motion.section {...fadeUp} style={{ paddingBottom: '5rem' }}>
          <h2 className="section-title">Hardware <span className="gradient-text">Security Foundation</span></h2>
          <p className="section-subtitle">
            Security starts at silicon. ARM TrustZone provides the hardware root of trust.
          </p>
          <div className="grid-2">
            {[
              { title: 'ARM TrustZone', desc: 'Hardware isolation between secure and non-secure worlds. Cryptographic keys never leave the Secure Enclave. CITADEL runtime operates in the secure world.', tags: ['Secure World', 'HW Isolation'] },
              { title: 'Secure Enclave', desc: 'Dedicated security processor for key storage, biometric validation, and attestation. Ed25519 signing keys hardware-bound.', tags: ['Ed25519', 'Biometric'] },
              { title: 'TPM Integration', desc: 'Trusted Platform Module for measured boot, platform integrity verification, and sealed storage. Boot chain hashed into WORM log.', tags: ['Measured Boot', 'WORM'] },
              { title: 'RIL Isolation', desc: 'Radio Interface Layer runs as an isolated user-space process. Baseband has zero access to application memory or CITADEL governance data.', tags: ['User-space', 'No Kernel'] },
            ].map(item => (
              <div key={item.title} className="glass-card">
                <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.75rem' }}>{item.title}</h3>
                <p style={{ color: '#8892a8', fontSize: '0.85rem', lineHeight: 1.65, marginBottom: '0.75rem' }}>{item.desc}</p>
                <div style={{ display: 'flex', gap: '0.4rem' }}>
                  {item.tags.map(t => <span key={t} className="tech-tag">{t}</span>)}
                </div>
              </div>
            ))}
          </div>
        </motion.section>

        {/* Mobile Roadmap */}
        <motion.section {...fadeUp} style={{ paddingBottom: '5rem' }}>
          <h2 className="section-title">Mobile <span className="gradient-text">Roadmap</span></h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            {mobilePhases.map((p, i) => (
              <motion.div
                key={p.phase}
                className="glass-card"
                initial={{ opacity: 0, x: -30 }}
                whileInView={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.1, duration: 0.4 }}
                viewport={{ once: true }}
                style={{ borderLeft: `3px solid ${i === 0 ? '#10b981' : '#1e293b'}` }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '0.5rem' }}>
                  <span style={{ fontFamily: 'var(--mono)', fontSize: '0.85rem', fontWeight: 700, color: '#10b981' }}>
                    {p.phase}
                  </span>
                  <span style={{ fontWeight: 600, fontSize: '1rem' }}>{p.target}</span>
                  {i === 0 && <span className="badge badge-planned">Next</span>}
                </div>
                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                  {p.items.map(item => <span key={item} className="tech-tag">{item}</span>)}
                </div>
              </motion.div>
            ))}
          </div>
        </motion.section>

        {/* EU Compliance */}
        <motion.section {...fadeUp} style={{ paddingBottom: '6rem' }}>
          <h2 className="section-title">EU <span className="gradient-text">Regulatory Compliance</span></h2>
          <p className="section-subtitle">
            MVNO operations touch critical infrastructure &mdash; NIS2 Article 21 applies fully.
          </p>
          <div className="grid-3">
            {[
              { reg: 'NIS2 Directive', desc: 'Every SIM activation and data policy change is a governance event. Article 21 measures enforced at OS level through CITADEL controls.' },
              { reg: 'GDPR', desc: 'User data isolation via grid sandboxes. CDR records hashed and stored in WORM chain. PII cannot leak between operator and application cells.' },
              { reg: 'Cyber Resilience Act', desc: 'Secure-by-default mobile configuration. Hardware-attested boot chain. OTA updates governed by MARSHAL gates.' },
              { reg: 'ePrivacy Regulation', desc: 'Communications metadata protected at OS level. VoIP encrypted end-to-end with hash integrity verification in WORM log.' },
              { reg: 'EECC (EU Telecom Code)', desc: 'Regulatory proof of policy enforcement for national telecom authorities. WORM chain provides immutable compliance evidence.' },
              { reg: 'eIDAS 2.0', desc: 'Digital identity wallets secured in ARM TrustZone Secure Enclave. CITADEL MARSHAL governs identity lifecycle operations.' },
            ].map(r => (
              <div key={r.reg} className="glass-card">
                <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: '#10b981', marginBottom: '0.5rem' }}>{r.reg}</h3>
                <p style={{ color: '#8892a8', fontSize: '0.83rem', lineHeight: 1.6 }}>{r.desc}</p>
              </div>
            ))}
          </div>
        </motion.section>

        {/* Footer */}
        <footer style={{
          borderTop: '1px solid rgba(0,240,255,0.06)',
          padding: '3rem 0', textAlign: 'center', color: '#64748b', fontSize: '0.85rem',
        }}>
          <p>
            <strong style={{
              background: 'linear-gradient(135deg, #10b981, #00f0ff)',
              WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', fontWeight: 800,
            }}>CitadelOS Mobile</strong>{' '}
            &mdash; Part of the <Link to="/" style={{ color: '#00f0ff' }}>SIN</Link> ecosystem.
            &middot; <Link to="/citadelos" style={{ color: '#8892a8' }}>Desktop Edition</Link>
          </p>
        </footer>
      </div>
    </div>
  )
}
