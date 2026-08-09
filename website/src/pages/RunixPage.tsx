import { lazy, Suspense } from 'react'
import { Link } from 'react-router-dom'
import { Helmet } from 'react-helmet-async'
import { motion } from 'framer-motion'
import { desktopLayers, sandboxTiers, osPhases } from '../data/runix'

const DesktopScene = lazy(() => import('../scene/DesktopScene'))

const fadeUp = {
  initial: { opacity: 0, y: 40 },
  whileInView: { opacity: 1, y: 0 },
  transition: { duration: 0.6, ease: [0.25, 0.1, 0.25, 1] },
  viewport: { once: true as const, margin: '-80px' },
}

export default function RunixPage() {
  return (
    <div style={{ background: 'var(--bg)', minHeight: '100vh' }}>
      <Helmet>
        <title>Runix — Rust Microkernel Security OS | opensecstack</title>
        <meta
          name="description"
          content="Runix is a Rust microkernel and WebAssembly operating system with CITADEL governance built in natively — isolated drivers, cryptographic grid sandboxes, and a WORM-verified boot chain."
        />
        <link rel="canonical" href="https://opensecstack.github.io/opensecstack/runix" />
        <meta property="og:url" content="https://opensecstack.github.io/opensecstack/runix" />
        <meta property="og:title" content="Runix — Rust Microkernel Security OS | opensecstack" />
        <meta
          property="og:description"
          content="A Rust microkernel + WebAssembly OS built for security from the ground up, with CITADEL governance running natively at the kernel level."
        />
      </Helmet>
      <Suspense fallback={null}>
        <DesktopScene />
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
        <span style={{ color: '#00f0ff', fontWeight: 600, fontSize: '0.95rem' }}>Runix</span>
        <Link to="/" style={{
          marginLeft: 'auto', color: '#8892a8', textDecoration: 'none', fontSize: '0.85rem',
        }}>
          Back to Ecosystem
        </Link>
      </nav>

      <div className="scroll-content" style={{ maxWidth: 1200, margin: '0 auto', padding: '0 2rem' }}>

        {/* Hero */}
        <section style={{ paddingTop: '12rem', paddingBottom: '6rem' }}>
          <motion.div initial={{ opacity: 0, y: 50 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.8 }}>
            <div style={{
              display: 'inline-block', padding: '5px 14px', borderRadius: 8, marginBottom: '1.5rem',
              background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)',
              fontSize: '0.8rem', fontFamily: 'var(--mono)', color: '#ef4444', letterSpacing: '0.08em',
            }}>
              Phase 5 &middot; OS Alpha 2027
            </div>
            <h1 style={{
              fontSize: 'clamp(2.8rem, 7vw, 5rem)', fontWeight: 800,
              letterSpacing: '-0.04em', lineHeight: 1.05,
            }}>
              <span className="gradient-text">Runix</span>
            </h1>
            <p style={{ fontSize: '1.5rem', color: '#e2e8f0', marginTop: '0.5rem', fontWeight: 500 }}>
              The Secure Operating System
            </p>
            <p style={{ marginTop: '1.5rem', fontSize: '1.1rem', color: '#8892a8', lineHeight: 1.7, maxWidth: 600 }}>
              A Rust microkernel + WebAssembly OS built for security from the ground up &mdash; not bolted on after the fact.
              CITADEL governance runs natively inside the OS. Drivers, filesystems, and apps
              run as isolated Rust processes or WebAssembly modules.
            </p>

            <div className="stat-grid" style={{ marginTop: '2.5rem' }}>
              {[
                { v: '~50K', l: 'LOC in kernel' },
                { v: '6', l: 'Security Layers' },
                { v: '3', l: 'Sandbox Tiers' },
                { v: '0', l: 'Drivers in Kernel' },
              ].map(s => (
                <div className="stat-item" key={s.l}>
                  <div className="stat-value">{s.v}</div>
                  <div className="stat-label">{s.l}</div>
                </div>
              ))}
            </div>
          </motion.div>
        </section>

        {/* Why */}
        <motion.section {...fadeUp} style={{ paddingBottom: '5rem' }}>
          <h2 className="section-title">Why Build a Secure OS <span className="gradient-text">From Scratch?</span></h2>
          <div className="grid-2">
            <div className="glass-card">
              <h3 style={{ color: '#ef4444', fontSize: '1.1rem', marginBottom: '0.75rem' }}>The Problem</h3>
              <p style={{ color: '#8892a8', fontSize: '0.9rem', lineHeight: 1.7 }}>
                Modern operating systems have <strong style={{ color: '#e2e8f0' }}>millions of lines</strong> running
                in privileged kernel space. A single driver vulnerability compromises the entire system.
                Security is patched on top, not built in.
              </p>
            </div>
            <div className="glass-card">
              <h3 style={{ color: '#10b981', fontSize: '1.1rem', marginBottom: '0.75rem' }}>Runix Approach</h3>
              <p style={{ color: '#8892a8', fontSize: '0.9rem', lineHeight: 1.7 }}>
                Rust microkernel: only IPC, memory management, and thread scheduling in kernel space (~50K LOC).
                <strong style={{ color: '#e2e8f0' }}> Everything else</strong> &mdash; drivers, filesystems,
                network &mdash; runs as isolated Rust user-space processes or WebAssembly modules.
              </p>
            </div>
          </div>
        </motion.section>

        {/* 6 Security Layers */}
        <motion.section {...fadeUp} style={{ paddingBottom: '5rem' }}>
          <h2 className="section-title">Desktop OS &mdash; <span className="gradient-text">6 Security Layers</span></h2>
          <p className="section-subtitle">
            From bare metal to application &mdash; every layer enforces isolation and governance.
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {desktopLayers.map((layer, i) => (
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
                    width: 36, height: 36, borderRadius: 8,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    background: `${layer.color}15`, border: `1px solid ${layer.color}30`,
                    fontFamily: 'var(--mono)', fontSize: '0.85rem', fontWeight: 700, color: layer.color,
                    flexShrink: 0,
                  }}>
                    L{layer.number}
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

        {/* Grid Sandbox */}
        <motion.section {...fadeUp} style={{ paddingBottom: '5rem' }}>
          <h2 className="section-title">Grid Sandboxes &mdash; <span className="gradient-text">Cryptographic Isolation</span></h2>
          <p className="section-subtitle">
            Applications live in cryptographically isolated cells. All inter-cell communication requires
            CITADEL MARSHAL-issued channel permits &mdash; signed, time-bounded, and audited in the WORM log.
          </p>
          <div className="grid-3">
            {sandboxTiers.map(tier => (
              <div key={tier.tier} className="glass-card" style={{ borderTop: `2px solid ${tier.color}` }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
                  <div style={{
                    width: 28, height: 28, borderRadius: 6,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    background: `${tier.color}18`, fontSize: '0.8rem', fontWeight: 700, color: tier.color,
                    fontFamily: 'var(--mono)',
                  }}>
                    T{tier.tier}
                  </div>
                  <h3 style={{ fontSize: '1.1rem', fontWeight: 700 }}>{tier.name}</h3>
                </div>
                <p style={{ color: '#8892a8', fontSize: '0.85rem', lineHeight: 1.6, marginBottom: '1rem' }}>
                  {tier.description}
                </p>
                <span className="tech-tag">{tier.marshalMode}</span>
              </div>
            ))}
          </div>
        </motion.section>

        {/* CITADEL Integration */}
        <motion.section {...fadeUp} style={{ paddingBottom: '5rem' }}>
          <h2 className="section-title"><span className="gradient-text">CITADEL</span> Native Integration</h2>
          <p className="section-subtitle">
            Governance is infrastructure, not application. CITADEL runs at the OS level.
          </p>
          <div className="grid-2">
            {[
              { title: 'MARSHAL at Boot', desc: 'Every kernel module and driver validated through MARSHAL gates before loading. Unsigned code never executes.', tag: '5-Gate' },
              { title: 'WORM Boot Chain', desc: 'Immutable hash chain from firmware to desktop shell. Any tampering detected and reported before user login.', tag: 'SHA-256' },
              { title: 'VIGIL System Health', desc: 'Real-time monitoring of all security layers. Degraded state triggers automatic isolation of affected subsystems.', tag: 'Real-time' },
              { title: 'AUGUR Advisories', desc: 'Threat intelligence feeds integrated at OS level. Known CVEs auto-matched against installed capabilities.', tag: 'Proactive' },
            ].map(item => (
              <div key={item.title} className="glass-card">
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.75rem' }}>
                  <h3 style={{ fontSize: '1rem', fontWeight: 700 }}>{item.title}</h3>
                  <span className="tech-tag">{item.tag}</span>
                </div>
                <p style={{ color: '#8892a8', fontSize: '0.85rem', lineHeight: 1.6 }}>{item.desc}</p>
              </div>
            ))}
          </div>
        </motion.section>

        {/* OS Roadmap */}
        <motion.section {...fadeUp} style={{ paddingBottom: '5rem' }}>
          <h2 className="section-title">OS <span className="gradient-text">Roadmap</span></h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            {osPhases.map((p, i) => (
              <motion.div
                key={p.phase}
                className="glass-card"
                initial={{ opacity: 0, x: -30 }}
                whileInView={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.1, duration: 0.4 }}
                viewport={{ once: true }}
                style={{ borderLeft: `3px solid ${i === 0 ? '#00f0ff' : '#1e293b'}` }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '0.5rem' }}>
                  <span style={{
                    fontFamily: 'var(--mono)', fontSize: '0.85rem', fontWeight: 700, color: '#00f0ff',
                  }}>
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

        {/* Mobile Edition CTA */}
        <motion.section {...fadeUp} style={{ paddingBottom: '5rem' }}>
          <div className="glass-card" style={{ borderColor: 'rgba(16,185,129,0.25)', textAlign: 'center', padding: '3rem 2rem' }}>
            <h2 style={{ fontSize: '1.8rem', fontWeight: 800, marginBottom: '0.75rem' }}>
              <span className="gradient-text">Runix Mobile</span>
            </h2>
            <p style={{ color: '#8892a8', fontSize: '1rem', lineHeight: 1.7, maxWidth: 520, margin: '0 auto 1.5rem' }}>
              ARM TrustZone, SIM governance, MVNO-native operations.
              The same microkernel security &mdash; built for mobile.
            </p>
            <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'center', flexWrap: 'wrap', marginBottom: '1.5rem' }}>
              <span className="tech-tag">ARM TrustZone</span>
              <span className="tech-tag">eSIM</span>
              <span className="tech-tag">MVNO Stack</span>
              <span className="tech-tag">VoIP</span>
              <span className="tech-tag">SIM Governance</span>
            </div>
            <Link to="/runix/mobile" style={{
              display: 'inline-block', padding: '12px 28px', borderRadius: 10, fontWeight: 600,
              fontSize: '0.95rem', background: 'rgba(16,185,129,0.1)',
              border: '1px solid rgba(16,185,129,0.3)', color: '#10b981', textDecoration: 'none',
            }}>
              Explore Mobile Edition &rarr;
            </Link>
          </div>
        </motion.section>

        {/* Compliance */}
        <motion.section {...fadeUp} style={{ paddingBottom: '6rem' }}>
          <h2 className="section-title">EU <span className="gradient-text">Compliance by Design</span></h2>
          <div className="grid-3">
            {[
              { reg: 'NIS2 Directive', desc: 'Article 21 security measures enforced at OS level through CITADEL controls.' },
              { reg: 'GDPR', desc: 'Data isolation via grid sandboxes. PII cannot leak between application cells.' },
              { reg: 'Cyber Resilience Act', desc: 'Secure-by-default configuration. Vulnerability management through AUGUR advisories.' },
            ].map(r => (
              <div key={r.reg} className="glass-card">
                <h3 style={{ fontSize: '1rem', fontWeight: 700, color: '#00f0ff', marginBottom: '0.5rem' }}>{r.reg}</h3>
                <p style={{ color: '#8892a8', fontSize: '0.85rem', lineHeight: 1.6 }}>{r.desc}</p>
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
              background: 'linear-gradient(135deg, #00f0ff, #7c3aed)',
              WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', fontWeight: 800,
            }}>Runix</strong>{' '}
            &mdash; Part of the <Link to="/" style={{ color: '#00f0ff' }}>SIN</Link> ecosystem.
            &middot; Desktop Edition
          </p>
        </footer>
      </div>
    </div>
  )
}
