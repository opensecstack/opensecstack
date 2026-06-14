export interface MobileLayer {
  number: number
  code: string
  name: string
  description: string
  color: string
}

export const mobileLayers: MobileLayer[] = [
  { number: 6, code: 'L6', name: 'User Interface',      description: 'Secure dialer, messaging, app launcher — all sandboxed cells.', color: '#00f0ff' },
  { number: 5, code: 'L5', name: 'App Runtime',          description: 'WebAssembly sandbox cells — each MARSHAL-gated. Apps compiled to WASM.', color: '#7c3aed' },
  { number: 4, code: 'L4', name: 'CITADEL Layer',        description: 'MARSHAL + VIGIL — SIM governance, roaming control, policy enforcement.', color: '#3b82f6' },
  { number: 3, code: 'L3', name: 'MVNO Stack',           description: 'Rust + WebAssembly. SIM provisioning, data policies, VoIP, eSIM lifecycle.', color: '#10b981' },
  { number: 2, code: 'L2', name: 'Radio Abstraction',    description: 'RIL (Radio Interface Layer) — isolated user-space process. No kernel access.', color: '#f59e0b' },
  { number: 1, code: 'L1', name: 'Microkernel + HW',     description: 'Rust microkernel + ARM TrustZone. Secure Enclave, TPM. Hardware-backed root of trust.', color: '#ef4444' },
]

export interface MVNOEvent {
  name: string
  flow: string
  gates: string
  outcome: string
  color: string
}

export const mvnoEvents: MVNOEvent[] = [
  {
    name: 'SIM Activation',
    flow: 'Kerkese submitted → MARSHAL Gate 1 (SoD: activator ≠ approver)',
    gates: 'Gate 1',
    outcome: 'EXECUTE → WORM entry → eSIM provisioned',
    color: '#00f0ff',
  },
  {
    name: 'Data Policy',
    flow: 'Policy change → Gate 2 (scope: contract type) → Gate 4 (evidence: regulatory ref)',
    gates: 'Gate 2 + 4',
    outcome: 'EXECUTE → WORM logged → policy applied',
    color: '#3b82f6',
  },
  {
    name: 'Roaming Config',
    flow: 'Roaming enable → Gate 1 (authority) + Gate 3 (change ID required)',
    gates: 'Gate 1 + 3',
    outcome: 'EXECUTE → WORM → CDR hash stored',
    color: '#10b981',
  },
  {
    name: 'VoIP Trunk',
    flow: 'Trunk config → all 5 gates evaluated',
    gates: 'All 5 Gates',
    outcome: 'EXECUTE + WORM → Real-time VIGIL health check on trunk status',
    color: '#7c3aed',
  },
  {
    name: 'Emergency Block',
    flow: 'SoD violation detected → HARD_STOP immediately',
    gates: 'HARD_STOP',
    outcome: 'WORM logged unconditionally → AUG-008 raised → ops alerted',
    color: '#ef4444',
  },
]

export interface MVNOFeature {
  title: string
  description: string
  tags: string[]
}

export const mvnoFeatures: MVNOFeature[] = [
  { title: 'SIM Provisioning', description: 'Full SIM lifecycle management with cryptographic Kerkese submission, MARSHAL evaluation, and immutable WORM audit trail.', tags: ['MARSHAL', 'WORM', 'Tier 1'] },
  { title: 'eSIM Management', description: 'Remote eSIM provisioning and profile switching. Every profile change governed by CITADEL with full audit trail.', tags: ['eSIM', 'Remote', 'Audit'] },
  { title: 'Data Policies', description: 'Per-user and per-service data allowances. Policy changes require regulatory evidence reference through Gate 4.', tags: ['Gate 4', 'Evidence', 'NIS2'] },
  { title: 'VoIP Integration', description: 'Voice over IP through MVNO network. Calls encrypted end-to-end with hash integrity verification.', tags: ['Encrypted', 'Hashed', 'VIGIL'] },
  { title: 'Roaming Agreements', description: 'Roaming configuration enforces Separation of Duties. CDR hashes stored in WORM chain for regulatory proof.', tags: ['SoD', 'CDR', 'WORM'] },
  { title: 'Network Slicing', description: 'Isolated network slices per service tier. Each slice operates within a dedicated CITADEL-governed sandbox.', tags: ['Isolation', 'Tier 1', 'Sandbox'] },
]

export const mobilePhases = [
  { phase: 'Alpha', target: '2027 Q2', items: ['Rust + ARM TrustZone boot', 'RIL isolation', 'WASM runtime', 'Basic SIM provisioning', 'CITADEL runtime stub'] },
  { phase: 'Beta',  target: '2027 Q4', items: ['MVNO stack core', 'eSIM lifecycle', 'Data policy engine', 'MARSHAL integration'] },
  { phase: 'RC',    target: '2028 Q2', items: ['Secure dialer', 'VoIP trunk', 'Roaming governance', 'VIGIL health monitoring'] },
  { phase: 'v1.0',  target: '2028 Q4', items: ['Full MVNO operations', 'NIS2 compliance suite', 'Network slicing', 'EU regulatory alignment'] },
]
