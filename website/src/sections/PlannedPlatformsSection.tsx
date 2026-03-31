import { motion } from 'framer-motion'
import ScrollSection from '../components/ScrollSection'

interface PlannedPlatform {
  name: string
  tagline: string
  color: string
  phase: string
  description: string
  features: string[]
  integrations: string[]
}

const planned: PlannedPlatform[] = [
  {
    name: 'ThreatFlow',
    tagline: 'Threat Intelligence Platform',
    color: '#ef4444',
    phase: 'Phase 4',
    description: 'Real-time IOC ingestion, correlation engine, and STIX/TAXII sharing. Feeds threat intelligence into all SIN platforms for threat-informed defence.',
    features: ['IOC feed aggregation', 'TTP mapping (MITRE ATT&CK)', 'STIX 2.1 bundles', 'TAXII 2.1 server', 'Automated correlation', 'Alert scoring'],
    integrations: ['APIGuard — scan prioritisation', 'IRFlow — incident enrichment', 'NIS2 Compass — threat context', 'CITADEL — WORM audit'],
  },
  {
    name: 'IRFlow',
    tagline: 'Incident Response Platform',
    color: '#f59e0b',
    phase: 'Phase 4',
    description: 'Structured incident management with automated playbooks, evidence chain, and stakeholder notification. Full incident lifecycle from detection to post-mortem.',
    features: ['Playbook automation', 'Evidence chain (hash-linked)', 'SLA tracking', 'Stakeholder notifications', 'Post-mortem reports', 'CSIRT coordination'],
    integrations: ['ThreatFlow — IOC enrichment', 'APIGuard — vulnerability context', 'NIS2 Compass — compliance evidence', 'CITADEL — governance audit'],
  },
  {
    name: 'OpenScrub',
    tagline: 'Data Sanitisation Engine',
    color: '#10b981',
    phase: 'Phase 5',
    description: 'Automated PII detection and sanitisation for logs, databases, and file exports. GDPR Article 17 right-to-erasure enforcement at infrastructure level.',
    features: ['PII detection (NER + regex)', 'Log sanitisation', 'Database redaction', 'File export filtering', 'GDPR erasure proof', 'Audit trail'],
    integrations: ['NIS2 Compass — data protection evidence', 'CITADEL — sanitisation governance', 'IRFlow — incident data cleanup'],
  },
  {
    name: 'CyberPath',
    tagline: 'Security Training Platform',
    color: '#e040fb',
    phase: 'Phase 5',
    description: 'Hands-on cybersecurity training with interactive labs, skill assessments, and certification tracking. Aligned with ENISA cybersecurity skills framework.',
    features: ['Interactive labs', 'Skill assessments', 'Certification tracking', 'ENISA framework alignment', 'Team progress dashboard', 'Custom curricula'],
    integrations: ['SecureLab — lab environments', 'APIGuard — API security labs', 'NIS2 Compass — compliance training'],
  },
  {
    name: 'SecureLab',
    tagline: 'Sandbox Environment',
    color: '#06b6d4',
    phase: 'Phase 5',
    description: 'Isolated sandbox environments for malware analysis, vulnerability research, and security testing. Containerised with CITADEL-governed lifecycle.',
    features: ['Malware analysis sandbox', 'Network traffic capture', 'Automated detonation', 'IOC extraction', 'Snapshot & rollback', 'API for automation'],
    integrations: ['ThreatFlow — IOC submission', 'CyberPath — training labs', 'IRFlow — forensic analysis', 'CITADEL — sandbox governance'],
  },
  {
    name: 'OpenCSIRT',
    tagline: 'CSIRT Operations Platform',
    color: '#8b5cf6',
    phase: 'Phase 5',
    description: 'Computer Security Incident Response Team operations for EU member states. Cross-border incident coordination aligned with NIS2 Directive reporting requirements.',
    features: ['Multi-CSIRT coordination', 'NIS2 incident reporting (24h/72h)', 'Cross-border sharing', 'Vulnerability disclosure', 'Situational awareness', 'EU-wide dashboard'],
    integrations: ['IRFlow — incident handoff', 'ThreatFlow — shared IOCs', 'NIS2 Compass — regulatory reporting', 'CITADEL — governance chain'],
  },
]

export default function PlannedPlatformsSection() {
  return (
    <ScrollSection id="planned">
      <h2 className="section-title">Coming <span className="gradient-text">Next</span></h2>
      <p className="section-subtitle">
        6 platforms in development — completing the SIN ecosystem for full-spectrum
        cybersecurity and EU Digital Decade compliance.
      </p>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
        {planned.map((p, i) => (
          <motion.div
            key={p.name}
            className="glass-card"
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.06, duration: 0.5 }}
            viewport={{ once: true }}
            style={{ borderLeft: `3px solid ${p.color}` }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
              <div style={{
                width: 10, height: 10, borderRadius: '50%',
                background: p.color, boxShadow: `0 0 12px ${p.color}88`,
              }} />
              <h3 style={{ fontSize: '1.2rem', fontWeight: 700 }}>{p.name}</h3>
              <span style={{ fontSize: '0.85rem', color: '#8892a8' }}>{p.tagline}</span>
              <span className="badge badge-planned">{p.phase}</span>
            </div>

            <p style={{ color: '#8892a8', fontSize: '0.9rem', lineHeight: 1.65, marginBottom: '1.25rem', maxWidth: 700 }}>
              {p.description}
            </p>

            <div className="grid-2" style={{ gap: '1rem' }}>
              <div>
                <div style={{ fontSize: '0.75rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '0.5rem' }}>
                  Features
                </div>
                <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                  {p.features.map(f => (
                    <span key={f} className="tech-tag">{f}</span>
                  ))}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '0.75rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '0.5rem' }}>
                  Integrations
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
                  {p.integrations.map(int => (
                    <div key={int} style={{ fontSize: '0.82rem', color: '#94a3b8', display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span style={{ color: p.color, fontSize: '0.7rem' }}>&#9656;</span> {int}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </motion.div>
        ))}
      </div>
    </ScrollSection>
  )
}
