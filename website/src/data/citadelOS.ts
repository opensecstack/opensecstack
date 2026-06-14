export interface OSLayer {
  number: number
  name: string
  description: string
  color: string
}

export const desktopLayers: OSLayer[] = [
  { number: 1, name: 'Microkernel',        description: 'Written in Rust. IPC, memory management, thread scheduling. ~50K LOC in privileged space.', color: '#ef4444' },
  { number: 2, name: 'Capability Manager',  description: 'Capability-based access control. Every resource access requires a signed, time-bounded capability token.', color: '#f59e0b' },
  { number: 3, name: 'OS Services',         description: 'Rust user-space daemons + WebAssembly sandboxed plugins. Filesystems, network, audio — all isolated.', color: '#10b981' },
  { number: 4, name: 'Grid Sandbox',        description: 'WebAssembly runtime for app isolation. Cryptographic cells with MARSHAL-issued channel permits.', color: '#3b82f6' },
  { number: 5, name: 'CITADEL Runtime',     description: 'MARSHAL 5-gate evaluation, WORM audit chain, VIGIL health monitoring — governance as infrastructure.', color: '#7c3aed' },
  { number: 6, name: 'Application Layer',   description: 'Apps compiled to WebAssembly run in sandboxed cells. Zero trust — all privileged ops go through MARSHAL.', color: '#00f0ff' },
]

export interface SandboxTier {
  tier: number
  name: string
  description: string
  marshalMode: string
  color: string
}

export const sandboxTiers: SandboxTier[] = [
  { tier: 1, name: 'Critical',    description: 'System daemons, crypto, key management. MARSHAL second-hand evaluation (<300ms).', marshalMode: 'Real-time', color: '#ef4444' },
  { tier: 2, name: 'Trusted',     description: 'First-party applications. Cell-to-cell communication with signed channel permits.', marshalMode: 'Standard', color: '#f59e0b' },
  { tier: 3, name: 'Untrusted',   description: 'Third-party apps, web content. MARSHAL with evidence requirement (minute-hand).', marshalMode: 'Evidence-gated', color: '#10b981' },
]

export const osPhases = [
  { phase: 'Alpha',   target: '2027 Q1', items: ['Rust microkernel boot', 'Capability manager', 'Basic IPC', 'WASM runtime', 'CITADEL runtime stub'] },
  { phase: 'Beta',    target: '2027 Q3', items: ['Grid sandbox isolation', 'Network stack (user-space)', 'Filesystem driver', 'MARSHAL integration'] },
  { phase: 'RC',      target: '2028 Q1', items: ['Desktop shell', 'Application framework', 'WORM chain boot verification', 'Hardware attestation'] },
  { phase: 'v1.0',    target: '2028 Q3', items: ['NIS2/GDPR compliance suite', 'Secure update channel', 'Full MARSHAL governance', 'EU Cyber Resilience Act alignment'] },
]
