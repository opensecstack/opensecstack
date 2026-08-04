import { motion } from 'framer-motion'
import type { ReactNode } from 'react'

interface Props {
  id?: string
  children: ReactNode
  className?: string
}

// Canonical reveal timing for section-level whileInView animations.
// Other components (e.g. PlatformCard) should import these so their own
// inner stagger animations trigger in sync with the section's reveal,
// instead of each file inventing its own viewport margin/easing.
export const SECTION_DURATION = 0.7
export const SECTION_EASE: [number, number, number, number] = [0.25, 0.1, 0.25, 1]
export const SECTION_VIEWPORT_MARGIN = '-100px'

export const motionConfig = {
  duration: SECTION_DURATION,
  ease: SECTION_EASE,
  viewportMargin: SECTION_VIEWPORT_MARGIN,
} as const

export default function ScrollSection({ id, children, className = '' }: Props) {
  return (
    <motion.section
      id={id}
      className={`section ${className}`}
      initial={{ opacity: 0, y: 60 }}
      whileInView={{ opacity: 1, y: 0 }}
      transition={{ duration: SECTION_DURATION, ease: SECTION_EASE }}
      viewport={{ once: true, margin: SECTION_VIEWPORT_MARGIN }}
    >
      {children}
      <div className="glow-divider" />
    </motion.section>
  )
}
