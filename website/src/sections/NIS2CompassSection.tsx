import PlatformDetailSection, { GradientTitle } from '../components/PlatformDetailSection'
import { nis2Measures } from '../data/nis2Measures'

export default function NIS2CompassSection() {
  return (
    <PlatformDetailSection
      id="nis2compass"
      title={<GradientTitle>NIS2 Compass</GradientTitle>}
      subtitle="Assess and document your organization's NIS2 compliance, control by control, with an audit trail regulators can trust — covering the full Article 21(2) assessment lifecycle, with 10 controls mapped to NIST CSF."
      left={
        <div className="glass-card">
          <h3 className="card-title" style={{ marginBottom: '1rem' }}>10 NIS2 Measures (Art. 21)</h3>
          {nis2Measures.map(m => (
            <div key={m.ref} style={{ display: 'flex', gap: 10, padding: '6px 0', fontSize: '0.85rem', borderBottom: '1px solid rgba(0,240,255,0.06)' }}>
              <span style={{ fontFamily: 'var(--mono)', color: '#7c3aed', fontWeight: 600, minWidth: 20 }}>{m.ref}</span>
              <span style={{ color: '#94a3b8' }}>{m.title}</span>
            </div>
          ))}
        </div>
      }
      right={
        <div className="glass-card">
          <h3 className="card-title" style={{ marginBottom: '1rem' }}>Assessment Lifecycle</h3>
          <div style={{ fontFamily: 'var(--mono)', fontSize: '0.85rem', color: '#94a3b8' }}>
            {['draft', 'in_progress', 'under_review', 'completed', 'archived'].map((s, i, arr) => (
              <div key={s} style={{ padding: '8px 0' }}>
                <span style={{ color: '#10b981' }}>{s}</span>
                {i < arr.length - 1 && <span style={{ color: '#334155', margin: '0 8px' }}>&rarr;</span>}
              </div>
            ))}
          </div>
          <div style={{ marginTop: '1.5rem' }}>
            <h4 className="card-title" style={{ marginBottom: '0.5rem' }}>Report Formats</h4>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <span className="tech-tag">PDF</span>
              <span className="tech-tag">JSON</span>
              <span className="tech-tag">SARIF 2.1.0</span>
            </div>
          </div>
        </div>
      }
    />
  )
}
