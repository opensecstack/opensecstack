import type { TechLine } from '../components/PlatformDetailSection'

/**
 * Content for the platform sections that follow the plain
 * "capabilities checklist + single architecture card" shape:
 * APIGuard, ThreatFlow, SecureLab, OpenScrub, SIN.
 */
export interface PlatformSectionData {
  id: string
  title: string
  subtitle: string
  capabilitiesHeading: string
  capabilities: string[]
  accentColor: string
  archLines: TechLine[]
}

export const apiGuardData: PlatformSectionData = {
  id: 'apiguard',
  title: 'APIGuard',
  subtitle: 'Automated API security scanning that checks every endpoint against the OWASP API Top 10, so vulnerabilities are caught before attackers find them.',
  capabilitiesHeading: 'OWASP API Top 10 Coverage',
  capabilities: [
    'A1 BOLA', 'A2 Broken Auth', 'A3 Mass Assignment', 'A4 Rate Limiting',
    'A5 Function Auth', 'A6 Business Flow', 'A7 SSRF', 'A8 Misconfiguration',
    'A9 Inventory', 'A10 Unsafe Consumption',
  ],
  accentColor: '#10b981',
  archLines: [
    { tag: 'L0', text: 'Rust-powered parsing, Go orchestration' },
    { tag: 'L1', text: 'Rust Parser (OpenAPI 3.x, Swagger 2.0)' },
    { tag: 'L2', text: 'Test Generation Engine' },
    { tag: 'L3', text: 'Rust Analysis Modules (OWASP)' },
    { tag: 'L4', text: 'CVSS 3.1 Scoring' },
    { tag: 'L5', text: 'Go HTTP Orchestration' },
    { tag: 'L6', text: 'PostgreSQL + Redis' },
    { tag: 'L7', text: 'Report Formats (PDF/JSON/SARIF)' },
  ],
}

export const threatFlowData: PlatformSectionData = {
  id: 'threatflow',
  title: 'ThreatFlow',
  subtitle: 'Real-time threat intelligence platform. IOC ingestion, correlation, and STIX/TAXII sharing so every connected platform blocks the same threats automatically.',
  capabilitiesHeading: 'Capabilities',
  capabilities: [
    'IOC feed aggregation', 'TTP mapping (MITRE ATT&CK)', 'STIX 2.1 bundles',
    'TAXII 2.1 server', 'Automated correlation', 'Alert scoring',
  ],
  accentColor: '#ef4444',
  archLines: [
    { tag: 'Ingest', text: 'Multi-source IOC feed aggregation' },
    { tag: 'Correlate', text: 'TTP mapping against MITRE ATT&CK' },
    { tag: 'Share', text: 'STIX 2.1 bundles via TAXII 2.1' },
    { tag: 'Score', text: 'Threat scoring with confidence levels' },
    { tag: 'Integrate', text: 'APIGuard, IRFlow, NIS2 Compass feeds' },
    { tag: 'Audit', text: 'CITADEL WORM chain for all events' },
  ],
}

export const secureLabData: PlatformSectionData = {
  id: 'securelab',
  title: 'SecureLab',
  subtitle: 'Isolated sandbox environments for malware analysis, vulnerability research, and security testing. Containerised with CITADEL-governed lifecycle.',
  capabilitiesHeading: 'Capabilities',
  capabilities: [
    'Malware analysis sandbox', 'Network traffic capture', 'Automated detonation',
    'IOC extraction', 'Snapshot & rollback', 'API for automation',
  ],
  accentColor: '#06b6d4',
  archLines: [
    { tag: 'Spawn', text: 'On-demand container creation' },
    { tag: 'Isolate', text: 'Network namespace + CITADEL sandbox' },
    { tag: 'Detonate', text: 'Automated malware execution' },
    { tag: 'Capture', text: 'Full packet + syscall tracing' },
    { tag: 'Extract', text: 'IOC export to ThreatFlow' },
    { tag: 'Destroy', text: 'Secure cleanup with WORM proof' },
  ],
}

export const openScrubData: PlatformSectionData = {
  id: 'openscrub',
  title: 'OpenScrub',
  subtitle: 'Stops DDoS floods before they reach your servers, using kernel-level XDP/eBPF packet filtering and GoBGP blackhole routing for volumetric attacks.',
  capabilitiesHeading: 'Capabilities',
  capabilities: [
    'XDP/eBPF kernel-level packet filtering', 'GoBGP blackhole routing',
    'FastNetMon detection integration', 'Per-source rate limiting',
    'Allowlist/blocklist management', 'CITADEL-governed rule lifecycle',
  ],
  accentColor: '#10b981',
  archLines: [
    { tag: 'Detect', text: 'FastNetMon flow analysis + threshold alerts' },
    { tag: 'Filter', text: 'XDP/eBPF programs at kernel ingress' },
    { tag: 'Blackhole', text: 'GoBGP RTBH announcements for volumetric' },
    { tag: 'Block', text: 'ThreatFlow IOC auto-block integration' },
    { tag: 'Validate', text: 'SecureLab DDoS rule simulation' },
    { tag: 'Audit', text: 'CITADEL WORM chain for all rule changes' },
  ],
}

export const sinData: PlatformSectionData = {
  id: 'sin',
  title: 'SIN Community',
  subtitle: 'Developer knowledge hub for the opensecstack ecosystem. A self-hosted community platform where practitioners share research, ask questions, and build the open-source security commons.',
  capabilitiesHeading: 'Capabilities',
  capabilities: [
    'Posts, comments & threaded discussions', 'Tag-based taxonomy & series',
    'Full-text search (Meilisearch)', 'Spaces (topic communities)',
    'Notifications & activity feed', 'TOTP 2FA & API keys',
  ],
  accentColor: '#22c55e',
  archLines: [
    { tag: 'API', text: 'Go HTTP server — chi · zap · pgx' },
    { tag: 'UI', text: 'React + TypeScript SPA' },
    { tag: 'Search', text: 'Meilisearch full-text index' },
    { tag: 'Auth', text: 'sinauth — OAuth2 / OIDC + TOTP 2FA' },
    { tag: 'Store', text: 'PostgreSQL 16 with JSONB' },
    { tag: 'Licence', text: 'Apache 2.0 — self-host freely' },
  ],
}
