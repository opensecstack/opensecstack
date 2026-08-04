import { Link } from 'react-router-dom'
import ScrollSection from '../components/ScrollSection'

export default function CitadelOSSection() {
  return (
    <ScrollSection id="citadelos">
      <h2 className="section-title"><span className="gradient-text">CitadelOS</span></h2>
      <p className="section-subtitle">
        A microkernel-based operating system built for security from the ground up.
        Every boot, driver load, and privileged syscall is gated by MARSHAL before it's allowed to run.
      </p>
      <div className="grid-2">
        {/* Desktop */}
        <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.75rem' }}>
              <h3 className="card-title">Desktop</h3>
              <span className="badge badge-planned">Phase 5</span>
            </div>
            <p style={{ color: '#8892a8', fontSize: '0.88rem', lineHeight: 1.7 }}>
              Rust microkernel (~50K LOC) + WebAssembly app isolation. 6 security layers.
              MARSHAL 5-gate at boot. WORM hash chain from firmware to shell.
            </p>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginTop: '1rem' }}>
              <span className="tech-tag">Rust</span>
              <span className="tech-tag">WebAssembly</span>
              <span className="tech-tag">Grid Sandbox</span>
              <span className="tech-tag">Secure Boot</span>
              <span className="tech-tag">TPM 2.0</span>
              <span className="tech-tag">Capability ACL</span>
              <span className="tech-tag">MARSHAL at Boot</span>
              <span className="tech-tag">WORM Chain</span>
            </div>
          </div>
          <Link to="/citadelos" style={{
            display: 'inline-block', marginTop: '1.5rem',
            padding: '10px 24px', borderRadius: 10, fontWeight: 600, fontSize: '0.9rem',
            background: 'rgba(0,240,255,0.08)', border: '1px solid rgba(0,240,255,0.25)',
            color: '#00f0ff', textDecoration: 'none', textAlign: 'center',
          }}>
            Desktop Edition &rarr;
          </Link>
        </div>

        {/* Mobile */}
        <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.75rem' }}>
              <h3 className="card-title">Mobile + MVNO</h3>
              <span className="badge badge-planned">Phase 5</span>
            </div>
            <p style={{ color: '#8892a8', fontSize: '0.88rem', lineHeight: 1.7 }}>
              Rust + ARM TrustZone hardware root of trust. Full MVNO stack with
              SIM/eSIM governance, VoIP, roaming, and data policies &mdash; all CITADEL-gated.
            </p>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginTop: '1rem' }}>
              <span className="tech-tag">MVNO</span>
              <span className="tech-tag">eSIM</span>
              <span className="tech-tag">SIM Governance</span>
              <span className="tech-tag">VoIP</span>
              <span className="tech-tag">Roaming</span>
              <span className="tech-tag">Rust</span>
              <span className="tech-tag">ARM TrustZone</span>
              <span className="tech-tag">WASM</span>
            </div>
          </div>
          <Link to="/citadelos/mobile" style={{
            display: 'inline-block', marginTop: '1.5rem',
            padding: '10px 24px', borderRadius: 10, fontWeight: 600, fontSize: '0.9rem',
            background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.25)',
            color: '#10b981', textDecoration: 'none', textAlign: 'center',
          }}>
            Mobile Edition &rarr;
          </Link>
        </div>
      </div>
    </ScrollSection>
  )
}
