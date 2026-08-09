import PlatformDetailSection, { CardStack, GradientTitle, TextCard } from '../components/PlatformDetailSection'
import { marshalGates } from '../data/marshalGates'

export default function CitadelSection() {
  return (
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
    />
  )
}
