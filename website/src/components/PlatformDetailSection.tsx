import type { ReactNode } from 'react'
import ScrollSection from './ScrollSection'

/**
 * Shared skeleton used by the 12 platform detail sections (APIGuard, ThreatFlow,
 * SecureLab, OpenScrub, SIN, CyberPath, VertGuard, IRFlow, OpenCSIRT, NIS2 Compass,
 * sinauth, CITADEL): a ScrollSection wrapper with a titled/subtitled header and a
 * two-column grid. `left` and `right` are fully custom so each platform can compose
 * whichever mix of the helper cards below (or bespoke JSX) it needs, while the
 * repeated wrapper/heading/grid markup lives in exactly one place.
 */
export default function PlatformDetailSection({
  id,
  title,
  subtitle,
  left,
  right,
  children,
}: {
  id: string
  title: ReactNode
  subtitle: ReactNode
  left: ReactNode
  right: ReactNode
  /** Extra content rendered after the grid (e.g. CitadelSection's Name Meaning card group). */
  children?: ReactNode
}) {
  return (
    <ScrollSection id={id}>
      <h2 className="section-title">{title}</h2>
      <p className="section-subtitle">{subtitle}</p>
      <div className="grid-2">
        {left}
        {right}
      </div>
      {children}
    </ScrollSection>
  )
}

/** Convenience wrapper: gradient-text title, no plain-text suffix. */
export function GradientTitle({ children }: { children: ReactNode }) {
  return <span className="gradient-text">{children}</span>
}

/** Left/right card: checklist of capabilities with a coloured checkmark. */
export function CapabilitiesCard({
  heading,
  items,
  accentColor,
}: {
  heading: string
  items: string[]
  accentColor: string
}) {
  return (
    <div className="glass-card">
      <h3 className="card-title" style={{ marginBottom: '1rem' }}>{heading}</h3>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
        {items.map(c => (
          <div key={c} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.85rem' }}>
            <span style={{ color: accentColor }}>&#10003;</span> {c}
          </div>
        ))}
      </div>
    </div>
  )
}

export interface TechLine {
  tag: string
  text: ReactNode
}

/** Right card: "Architecture"-style tech-tag lines. */
export function ArchitectureCard({
  heading = 'Architecture',
  lines,
  footer,
}: {
  heading?: string
  lines: TechLine[]
  footer?: ReactNode
}) {
  return (
    <div className="glass-card">
      <h3 className="card-title" style={{ marginBottom: '1rem' }}>{heading}</h3>
      <div style={{ fontFamily: 'var(--mono)', fontSize: '0.8rem', color: '#94a3b8', lineHeight: 2 }}>
        {lines.map((l, i) => (
          <div key={i}><span className="tech-tag">{l.tag}</span> {l.text}</div>
        ))}
      </div>
      {footer}
    </div>
  )
}

/** Small card: heading + a single paragraph of prose. */
export function TextCard({ heading, children }: { heading: string; children: ReactNode }) {
  return (
    <div className="glass-card">
      <h3 className="card-title" style={{ marginBottom: '0.5rem' }}>{heading}</h3>
      <p style={{ fontSize: '0.85rem', color: '#94a3b8', lineHeight: 1.6 }}>{children}</p>
    </div>
  )
}

/** Card: a left-to-right arrow chain of stage names (IRFlow lifecycle, NIS2 Compass states). */
export function FlowStepsCard({
  heading,
  steps,
  color,
}: {
  heading: string
  steps: string[]
  color: string
}) {
  return (
    <div className="glass-card">
      <h3 className="card-title" style={{ marginBottom: '0.5rem' }}>{heading}</h3>
      <div style={{ fontFamily: 'var(--mono)', fontSize: '0.85rem', color: '#94a3b8' }}>
        {steps.map((s, i, arr) => (
          <span key={s}>
            <span style={{ color }}>{s}</span>
            {i < arr.length - 1 && <span style={{ color: '#334155', margin: '0 6px' }}>&rarr;</span>}
          </span>
        ))}
      </div>
    </div>
  )
}

/** Vertical stack of cards for the right column when more than one card is needed. */
export function CardStack({ children }: { children: ReactNode }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {children}
    </div>
  )
}
