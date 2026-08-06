import { useEffect, useRef, useState } from 'react'
import * as THREE from 'three'
import NET from 'vanta/dist/vanta.net.min'
import type { VantaEffect } from 'vanta/dist/vanta.net.min'

/**
 * Mirrors the prefers-reduced-motion pattern used elsewhere in this codebase
 * (MediaVideo.tsx, the scene/ files): the effect isn't just slowed, it's
 * never initialized at all when the user has requested reduced motion.
 */
function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = useState(false)
  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
    const apply = () => setReduced(mq.matches)
    apply()
    mq.addEventListener('change', apply)
    return () => mq.removeEventListener('change', apply)
  }, [])
  return reduced
}

/**
 * Ambient "digital network" background: vanta.js's NET effect (glowing dots
 * connected by lines, drifting and reacting to mouse movement) — the
 * standard web equivalent of the After-Effects "Plexus" look. Mounted on
 * its own plain DOM element (vanta manages its own internal three.js
 * renderer/canvas, so this does NOT render inside an existing R3F
 * `<Canvas>`); intended to sit behind other content as a transparent
 * backdrop layer, e.g. behind EcosystemScene's own (alpha-enabled) canvas
 * so both show through together.
 *
 * Never initialized under prefers-reduced-motion (the effect is
 * continuously animating by nature — there's no meaningful "static" mode to
 * fall back to), leaving a plain transparent div instead.
 */
export default function VantaBackground() {
  const containerRef = useRef<HTMLDivElement>(null)
  const effectRef = useRef<VantaEffect | null>(null)
  const reducedMotion = usePrefersReducedMotion()

  useEffect(() => {
    if (reducedMotion || !containerRef.current) return

    effectRef.current = NET({
      el: containerRef.current,
      THREE,
      mouseControls: true,
      touchControls: true,
      gyroControls: false,
      minHeight: 200,
      minWidth: 200,
      scale: 1,
      scaleMobile: 1,
      color: 0x4fd1ff,
      backgroundAlpha: 0,
      points: 10,
      maxDistance: 22,
      spacing: 18,
      showDots: true,
    })

    return () => {
      effectRef.current?.destroy()
      effectRef.current = null
    }
  }, [reducedMotion])

  return (
    <div
      ref={containerRef}
      aria-hidden="true"
      style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', zIndex: 0, pointerEvents: 'none' }}
    />
  )
}
