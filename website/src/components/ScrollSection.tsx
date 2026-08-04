import { cubicBezier, motion, useReducedMotion, useScroll, useTransform } from 'framer-motion'
import type { ReactNode } from 'react'
import { useRef } from 'react'

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
  const ref = useRef<HTMLElement>(null)
  const prefersReducedMotion = useReducedMotion()

  // Track scroll progress of this section relative to the viewport:
  // 0 when the section's top edge is just entering at the bottom of the
  // viewport, 1 by the time it has scrolled ~25% of the viewport height
  // further up. This scrubs only the entrance reveal to scroll position —
  // once progress hits 1 the section stays fully revealed for the rest of
  // its time on screen (no re-hide, no continuous scroll-linked motion).
  const { scrollYProgress } = useScroll({
    target: ref,
    offset: ['start end', 'start 75%'],
  })

  // Approximate the existing SECTION_EASE cubic-bezier feel for the
  // scroll-scrubbed interpolation instead of a flat linear mapping.
  const sectionEase = cubicBezier(...SECTION_EASE)
  const opacity = useTransform(scrollYProgress, [0, 1], [0, 1], { ease: sectionEase })
  const y = useTransform(scrollYProgress, [0, 1], [60, 0], { ease: sectionEase })

  if (prefersReducedMotion) {
    return (
      <motion.section id={id} className={`section ${className}`}>
        {children}
        <div className="glow-divider" />
      </motion.section>
    )
  }

  return (
    <motion.section
      ref={ref}
      id={id}
      className={`section ${className}`}
      style={{ opacity, y }}
    >
      {children}
      <div className="glow-divider" />
    </motion.section>
  )
}
