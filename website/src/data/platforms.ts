export interface Platform {
  id: string
  name: string
  tagline: string
  description: string
  stack: string[]
  licence: 'Apache-2.0' | 'AGPL-3.0'
  status: 'active' | 'planned'
  color: string
  phase: number
  sectionId: string
}

export const platforms: Platform[] = [
  {
    id: 'apiguard',
    name: 'APIGuard',
    tagline: 'API Security Scanner',
    description: 'Automated OWASP API Top 10 detection with Rust-powered parsing and Go orchestration. CLI, REST API, and CI/CD integration.',
    stack: ['Go', 'Rust', 'PostgreSQL', 'React'],
    licence: 'Apache-2.0',
    status: 'active',
    color: '#00f0ff',
    phase: 1,
    sectionId: 'apiguard',
  },
  {
    id: 'nis2compass',
    name: 'NIS2 Compass',
    tagline: 'NIS2 Compliance Platform',
    description: 'Full NIS2 Article 21(2) assessment lifecycle with 10-control framework, NIST CSF mapping, and immutable audit trail.',
    stack: ['Python', 'Flask', 'PostgreSQL', 'React'],
    licence: 'AGPL-3.0',
    status: 'active',
    color: '#7c3aed',
    phase: 3,
    sectionId: 'nis2compass',
  },
  {
    id: 'threatflow',
    name: 'ThreatFlow',
    tagline: 'Threat Intelligence',
    description: 'IOC ingestion, correlation, and STIX/TAXII sharing for threat-informed defence.',
    stack: ['Go', 'Rust', 'Redis'],
    licence: 'Apache-2.0',
    status: 'planned',
    color: '#ef4444',
    phase: 4,
    sectionId: 'ecosystem',
  },
  {
    id: 'irflow',
    name: 'IRFlow',
    tagline: 'Incident Response',
    description: 'Structured incident management with playbook automation and evidence chain.',
    stack: ['Go', 'PostgreSQL'],
    licence: 'Apache-2.0',
    status: 'planned',
    color: '#f59e0b',
    phase: 4,
    sectionId: 'ecosystem',
  },
  {
    id: 'openscrub',
    name: 'OpenScrub',
    tagline: 'Data Sanitisation',
    description: 'Automated PII detection and sanitisation for logs, databases, and file exports.',
    stack: ['Python', 'Rust'],
    licence: 'Apache-2.0',
    status: 'planned',
    color: '#10b981',
    phase: 5,
    sectionId: 'ecosystem',
  },
  {
    id: 'cyberpath',
    name: 'CyberPath',
    tagline: 'Security Training',
    description: 'Hands-on cybersecurity training platform with labs and certification tracking.',
    stack: ['Go', 'React'],
    licence: 'AGPL-3.0',
    status: 'planned',
    color: '#e040fb',
    phase: 5,
    sectionId: 'ecosystem',
  },
  {
    id: 'securelab',
    name: 'SecureLab',
    tagline: 'Sandbox Environment',
    description: 'Isolated sandbox environments for malware analysis and security research.',
    stack: ['Go', 'Rust', 'Docker'],
    licence: 'Apache-2.0',
    status: 'planned',
    color: '#06b6d4',
    phase: 5,
    sectionId: 'ecosystem',
  },
  {
    id: 'opencsirt',
    name: 'OpenCSIRT',
    tagline: 'CSIRT Operations',
    description: 'Computer Security Incident Response Team operations platform for EU member states.',
    stack: ['Go', 'PostgreSQL'],
    licence: 'AGPL-3.0',
    status: 'planned',
    color: '#8b5cf6',
    phase: 5,
    sectionId: 'ecosystem',
  },
]

export const citadel = {
  id: 'citadel',
  name: 'CITADEL',
  tagline: 'Governance Engine',
  description: 'Immutable WORM audit chain, MARSHAL 5-gate evaluation, VIGIL health monitoring, and AUGUR advisory system.',
  stack: ['Go', 'PostgreSQL', 'Ed25519'],
  colour: '#00f0ff',
}
