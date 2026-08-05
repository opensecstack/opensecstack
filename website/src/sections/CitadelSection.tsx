import PlatformDetailSection, { CardStack, GradientTitle, TextCard } from '../components/PlatformDetailSection'
import { marshalGates } from '../data/marshalGates'
import WormChainVisual from '../scene/WormChainVisual'
import MarshalGatesPipeline from '../scene/MarshalGatesPipeline'
import TripleHashVisual from '../scene/TripleHashVisual'
import WormChainBackground from '../scene/WormChainBackground'

export default function CitadelSection() {
  return (
    <div style={{ position: 'relative' }}>
      <div style={{ position: 'absolute', inset: 0, zIndex: 0, pointerEvents: 'none', overflow: 'hidden' }}>
        <WormChainBackground opacity={0.5} />
      </div>
      <div style={{ position: 'relative', zIndex: 1 }}>
    <PlatformDetailSection
      id="citadel"
      title={<><GradientTitle>CITADEL</GradientTitle> Governance</>}
      subtitle="A fortified centre for the decisions and records that matter most — protecting audit truth, privileged actions, and institutional memory against tampering or loss."
      left={
        <div className="glass-card">
          <h3 className="card-title" style={{ marginBottom: '1rem' }}>MARSHAL — 5-Gate Evaluation</h3>
          {marshalGates.map(g => (
            <div key={g.number} style={{ display: 'flex', gap: 12, padding: '10px 0', borderBottom: '1px solid rgba(0,240,255,0.06)' }}>
              <div style={{
                width: 28, height: 28, borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center',
                background: 'rgba(0,240,255,0.1)', border: '1px solid rgba(0,240,255,0.2)',
                fontFamily: 'var(--mono)', fontSize: '0.8rem', color: '#00f0ff', fontWeight: 600, flexShrink: 0,
              }}>
                {g.number}
              </div>
              <div>
                <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>{g.name}</div>
                <div style={{ fontSize: '0.8rem', color: '#94a3b8' }}>{g.description}</div>
              </div>
            </div>
          ))}
        </div>
      }
      right={
        <CardStack>
          <TextCard heading="Name Meaning">
            A citadel is a fortified centre built to protect what matters. In fiction, it can mean a place where knowledge is preserved.
            In opensecstack, CITADEL is the cryptographic governance centre that protects audit truth, privileged decisions, and institutional memory.
          </TextCard>
          <TextCard heading="WORM Chain">
            Write-Once-Read-Many immutable audit log. SHA-256 hash chain with Ed25519 anchor rotation.
            Every governance decision is permanently recorded and tamper-detectable.
          </TextCard>
          <TextCard heading="VIGIL">
            Ecosystem health monitor — design-stage for v2.0. Not yet
            implemented; MARSHAL, WORM, NDS, and AUGUR above are live today.
          </TextCard>
          <TextCard heading="AUGUR">
            Behavioural heuristics evaluated at Gate 4: off-hours activity,
            high-frequency actions, and DATA_EXPORT requests without an
            associated incident. A focused rule set, not a general advisory engine.
          </TextCard>
        </CardStack>
      }
    >
      <div style={{ marginTop: '3rem' }}>
        <h3 className="card-title" style={{ marginBottom: '0.5rem' }}>Live Governance Mechanics</h3>
        <p style={{ fontSize: '0.85rem', color: '#94a3b8', lineHeight: 1.6, marginBottom: '1.5rem', maxWidth: '60ch' }}>
          Illustrative visualizations of how MARSHAL, WORM, and TripleHash
          actually work — not live data, but built on the real mechanics
          described above.
        </p>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem' }}>
          <div className="glass-card" style={{ padding: '1rem' }}>
            <h4 style={{ fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.5rem', color: '#e2e8f0' }}>
              MARSHAL — 5-Gate Pipeline
            </h4>
            <div style={{ height: 260, borderRadius: 8, overflow: 'hidden' }}>
              <MarshalGatesPipeline />
            </div>
          </div>
          <div className="glass-card" style={{ padding: '1rem' }}>
            <h4 style={{ fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.5rem', color: '#e2e8f0' }}>
              WORM — Audit Chain
            </h4>
            <div style={{ height: 260, borderRadius: 8, overflow: 'hidden' }}>
              <WormChainVisual />
            </div>
          </div>
          <div className="glass-card" style={{ padding: '1rem' }}>
            <h4 style={{ fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.5rem', color: '#e2e8f0' }}>
              TripleHash — Composite Digest
            </h4>
            <div style={{ height: 260, borderRadius: 8, overflow: 'hidden' }}>
              <TripleHashVisual />
            </div>
          </div>
        </div>
      </div>
    </PlatformDetailSection>
      </div>
    </div>
  )
}
