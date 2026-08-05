import { useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { useFrame, useThree } from '@react-three/fiber'
import * as THREE from 'three'
import { useScrollMax } from '../hooks/useScrollMax'

/**
 * Mirrors the prefers-reduced-motion pattern used in MediaVideo.tsx /
 * WormChainVisual.tsx: continuous decorative animation is frozen entirely
 * (not just slowed) when the user has requested reduced motion, while the
 * chain itself remains fully visible in a static arrangement.
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

// Deep-blue "digital chain" palette, matching the reference image: a solid,
// chunky, dark blue chain with a glowing cyan-blue plexus (dots + connecting
// lines) traced over its surface, rather than the earlier thin silver
// wireframe treatment.
const CHAIN_BLUE = '#13245e'
const CHAIN_BLUE_EMISSIVE = '#1e3a8a'
const PLEXUS_GLOW = '#4fd1ff'
const PLEXUS_GLOW_BRIGHT = '#bfe9ff'

const LINK_COUNT = 6
const TORUS_RADIUS = 0.85
const TORUS_TUBE = 0.32
// Smooth-ish solid geometry (this reference is a solid chunky chain, not a
// faceted wireframe) while staying cheap: moderate, not high-poly, segments.
const RADIAL_SEGMENTS = 10
const TUBULAR_SEGMENTS = 20
// How many points trace the glowing plexus ring around each link's core loop.
const PLEXUS_POINTS_PER_LINK = 14

interface LinkData {
  position: THREE.Vector3
  quaternion: THREE.Quaternion
}

/**
 * A tight, twisting serpentine curve the chain follows — links turn through
 * alternating perpendicular planes as they progress, echoing the reference
 * image's chain snaking through 3D space rather than sitting on a flat
 * diagonal line. Kept as a pure function of t so tangents can be derived by
 * sampling nearby points.
 */
function pathPoint(t: number): THREE.Vector3 {
  const x = -1.6 + t * 3.2
  const y = Math.sin(t * Math.PI * 1.6) * 1.4
  const z = -1.2 + Math.cos(t * Math.PI * 1.6) * 1.1
  return new THREE.Vector3(x, y, z)
}

/**
 * Lays out an unbroken, interlocking chain: each link's position follows
 * `pathPoint`, and its orientation is aligned so the ring's normal follows
 * the path tangent, with every other link additionally rolled 90° around a
 * perpendicular axis — the same alternating-perpendicular arrangement a
 * real chain uses to hook consecutive links through one another. Computed
 * once (not per frame), so a scratch Object3D here is not a per-frame
 * allocation concern.
 */
function buildLinks(count: number): LinkData[] {
  const dummy = new THREE.Object3D()
  const links: LinkData[] = []

  for (let i = 0; i < count; i++) {
    const t = count > 1 ? i / (count - 1) : 0
    const pos = pathPoint(t)
    const tangentA = pathPoint(Math.max(0, t - 0.01))
    const tangentB = pathPoint(Math.min(1, t + 0.01))
    const tangent = tangentB.clone().sub(tangentA).normalize()

    dummy.position.copy(pos)
    dummy.up.set(0, 1, 0)
    dummy.lookAt(pos.clone().add(tangent))
    if (i % 2 === 1) {
      // Perpendicular roll so alternating links interlock rather than
      // stacking in parallel planes.
      dummy.rotateX(Math.PI / 2)
    }

    links.push({
      position: pos,
      quaternion: dummy.quaternion.clone(),
    })
  }

  return links
}

/** The two ring traces per link (outer surface, top surface) that the glowing plexus follows. */
const PLEXUS_RING_V_OFFSETS = [0, Math.PI / 2]

/**
 * Traces a glowing "plexus" (dots + connecting lines) over each link's
 * surface: for each of a couple of ring positions around the tube, sample
 * `PLEXUS_POINTS_PER_LINK` points around the main torus angle by evaluating
 * the parametric surface directly (cheaper than reading back real geometry
 * vertices), and connect consecutive points into a closed ring so it reads
 * as a network traced over the solid chain rather than isolated stars.
 * Returns both the point positions (for glow dots) and a flat line-segment
 * buffer (point-pairs, one draw call for every ring on every link) so the
 * connecting lines match the reference image's "digital chain" look.
 */
function buildPlexusData(links: LinkData[]): {
  pointPositions: Float32Array
  linePositions: Float32Array
} {
  const ringsPerLink = PLEXUS_RING_V_OFFSETS.length
  const pointCount = links.length * ringsPerLink * PLEXUS_POINTS_PER_LINK
  const pointPositions = new Float32Array(pointCount * 3)
  // Each ring of N points has N connecting segments (closed loop), each segment = 2 points.
  const linePositions = new Float32Array(links.length * ringsPerLink * PLEXUS_POINTS_PER_LINK * 2 * 3)

  const local = new THREE.Vector3()
  const ringPoints: THREE.Vector3[] = Array.from({ length: PLEXUS_POINTS_PER_LINK }, () => new THREE.Vector3())
  let pi = 0
  let li = 0

  for (const link of links) {
    for (const v of PLEXUS_RING_V_OFFSETS) {
      const r = TORUS_RADIUS + TORUS_TUBE * Math.cos(v)
      const depth = TORUS_TUBE * Math.sin(v)

      for (let k = 0; k < PLEXUS_POINTS_PER_LINK; k++) {
        const u = (k / PLEXUS_POINTS_PER_LINK) * Math.PI * 2
        local.set(r * Math.cos(u), r * Math.sin(u), depth)
        local.applyQuaternion(link.quaternion)
        local.add(link.position)
        ringPoints[k].copy(local)

        pointPositions[pi++] = local.x
        pointPositions[pi++] = local.y
        pointPositions[pi++] = local.z
      }

      for (let k = 0; k < PLEXUS_POINTS_PER_LINK; k++) {
        const a = ringPoints[k]
        const b = ringPoints[(k + 1) % PLEXUS_POINTS_PER_LINK]
        linePositions[li++] = a.x
        linePositions[li++] = a.y
        linePositions[li++] = a.z
        linePositions[li++] = b.x
        linePositions[li++] = b.y
        linePositions[li++] = b.z
      }
    }
  }

  return { pointPositions, linePositions }
}

/**
 * Sparse, fully static thin diagonal lines scattered behind the chain to
 * suggest a background network — no per-frame updates, a single draw call.
 * Positions are derived deterministically (no Math.random) so the layout is
 * stable across renders.
 */
function buildNetworkSegments(count: number): Float32Array {
  const positions = new Float32Array(count * 2 * 3)
  for (let i = 0; i < count; i++) {
    const angle = i * 0.618033988749895 * Math.PI * 2
    const cx = Math.cos(angle * 1.3) * 5
    const cy = Math.sin(angle * 0.7) * 3
    const cz = -3 - (i % 3)
    const len = 2 + (i % 4) * 0.8
    const dx = Math.cos(angle) * len
    const dy = Math.sin(angle * 1.5) * len

    positions[i * 6 + 0] = cx - dx / 2
    positions[i * 6 + 1] = cy - dy / 2
    positions[i * 6 + 2] = cz
    positions[i * 6 + 3] = cx + dx / 2
    positions[i * 6 + 4] = cy + dy / 2
    positions[i * 6 + 5] = cz
  }
  return positions
}

interface ChainLinksProps {
  links: LinkData[]
  opacity: number
}

/** The solid, chunky chain links themselves — one shared geometry + material, deep blue with a subtle metallic sheen and emissive glow, matching the reference image's solid (not wireframe) chain body. */
function ChainLinks({ links, opacity }: ChainLinksProps) {
  const geometry = useMemo(
    () => new THREE.TorusGeometry(TORUS_RADIUS, TORUS_TUBE, RADIAL_SEGMENTS, TUBULAR_SEGMENTS),
    [],
  )
  const material = useMemo(
    () =>
      new THREE.MeshStandardMaterial({
        color: CHAIN_BLUE,
        emissive: CHAIN_BLUE_EMISSIVE,
        emissiveIntensity: 0.5,
        metalness: 0.6,
        roughness: 0.35,
        transparent: true,
        opacity: 0.85 * opacity,
      }),
    [opacity],
  )

  // Dispose geometry/material only on unmount (geometry is stable across
  // opacity changes) or when a new material instance replaces the old one.
  useEffect(() => () => geometry.dispose(), [geometry])
  useEffect(() => () => material.dispose(), [material])

  return (
    <>
      {links.map((link, i) => (
        <mesh key={i} position={link.position} quaternion={link.quaternion} geometry={geometry} material={material} />
      ))}
    </>
  )
}

interface ChainPlexusProps {
  links: LinkData[]
  reducedMotion: boolean
  opacity: number
}

/**
 * The glowing cyan-blue "plexus" traced over the solid chain's surface —
 * dots at sampled surface points connected by thin lines into rings that
 * follow each link's contour, pulsing very subtly. This is what gives the
 * reference image's "digital network over a physical chain" look, layered
 * on top of ChainLinks' solid mesh.
 */
function ChainPlexus({ links, reducedMotion, opacity }: ChainPlexusProps) {
  const { pointPositions, linePositions } = useMemo(() => buildPlexusData(links), [links])
  const pointsMaterialRef = useRef<THREE.PointsMaterial>(null)
  const lineMaterialRef = useRef<THREE.LineBasicMaterial>(null)
  const phaseRef = useRef(0)
  const basePointOpacity = 0.9 * opacity
  const baseLineOpacity = 0.35 * opacity

  useFrame((_state, delta) => {
    const pointsMat = pointsMaterialRef.current
    const lineMat = lineMaterialRef.current
    if (!pointsMat || !lineMat) return
    if (reducedMotion) {
      pointsMat.opacity = basePointOpacity
      pointsMat.size = 0.05
      lineMat.opacity = baseLineOpacity
      return
    }
    phaseRef.current += delta * 0.5
    const pulse = 0.5 + 0.5 * Math.sin(phaseRef.current)
    pointsMat.opacity = basePointOpacity * (0.6 + 0.4 * pulse)
    pointsMat.size = 0.04 + 0.025 * pulse
    lineMat.opacity = baseLineOpacity * (0.7 + 0.3 * pulse)
  })

  return (
    <>
      <points>
        <bufferGeometry>
          <bufferAttribute attach="attributes-position" count={pointPositions.length / 3} array={pointPositions} itemSize={3} />
        </bufferGeometry>
        <pointsMaterial
          ref={pointsMaterialRef}
          color={PLEXUS_GLOW_BRIGHT}
          size={0.05}
          sizeAttenuation
          transparent
          opacity={basePointOpacity}
          blending={THREE.AdditiveBlending}
          depthWrite={false}
          toneMapped={false}
        />
      </points>
      <lineSegments>
        <bufferGeometry>
          <bufferAttribute attach="attributes-position" count={linePositions.length / 3} array={linePositions} itemSize={3} />
        </bufferGeometry>
        <lineBasicMaterial
          ref={lineMaterialRef}
          color={PLEXUS_GLOW}
          transparent
          opacity={baseLineOpacity}
          blending={THREE.AdditiveBlending}
          depthWrite={false}
          toneMapped={false}
        />
      </lineSegments>
    </>
  )
}

interface NetworkLinesProps {
  opacity: number
}

function NetworkLines({ opacity }: NetworkLinesProps) {
  const positions = useMemo(() => buildNetworkSegments(9), [])
  return (
    <lineSegments>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" count={positions.length / 3} array={positions} itemSize={3} />
      </bufferGeometry>
      <lineBasicMaterial color={PLEXUS_GLOW} transparent opacity={0.1 * opacity} />
    </lineSegments>
  )
}

interface ScrollBounceSpinGroupProps {
  reducedMotion: boolean
  children: ReactNode
}

/** Continuous self-spin speed around the Y axis, in radians/second — always
 * active (like CitadelFortress's own idle rotation), independent of scroll. */
const SPIN_SPEED = 0.5
/** Half-extent margins (world units) so the chain's own visual bulk stays
 * on-screen at the bounds rather than its center touching the literal edge. */
const BOUNCE_MARGIN_X = 2.2
const BOUNCE_MARGIN_Y = 2.6
/** How many full left-right traversals happen across one full page scroll
 * (top to bottom). */
const LEGS_PER_PAGE = 14
/** Vertical step applied at each left/right collision (a completed leg),
 * randomized-looking within this pixel range via a deterministic per-leg
 * hash (not Math.random()) so the position stays a pure, stable function of
 * scroll progress — scrolling back up must retrace the same path exactly,
 * not jitter. */
const MIN_STEP_PX = 50
const MAX_STEP_PX = 100

/** Deterministic pseudo-random-looking step size for leg index `i`, in the
 * 50-100px range — a simple integer hash, not Math.random(), so it's stable
 * across re-renders and re-computable from scroll position alone. */
function stepPxForLeg(i: number): number {
  const range = MAX_STEP_PX - MIN_STEP_PX + 1
  const hash = (i * 7919 + 104729) % range
  return MIN_STEP_PX + hash
}

/**
 * Continuously self-spins the chain (Y-axis rotation, matching
 * CitadelFortress's own idle rotation — never stops, independent of scroll)
 * while its position sweeps left-right across the visible scene bounds tied
 * directly to page scroll progress: at scrollY=0 it sits at the left edge,
 * and as the user scrolls it sweeps to the right edge, bounces back left,
 * and so on for LEGS_PER_PAGE traversals across the full page height. Each
 * completed traversal ("collision" with an edge) steps the chain's vertical
 * position by a deterministic 50-100px (converted to world units) — when
 * the cumulative descent would exceed the visible vertical range, the fold
 * reverses (climbing back toward the top), continuing indefinitely as a
 * pure function of scroll position (so scrolling up retraces the same
 * path). Frozen entirely (static top-left pose, no rotation) under
 * prefers-reduced-motion.
 */
function ScrollBounceSpinGroup({ reducedMotion, children }: ScrollBounceSpinGroupProps) {
  const groupRef = useRef<THREE.Group>(null)
  const { viewport, size } = useThree()
  const scrollMax = useScrollMax()

  useFrame((_state, delta) => {
    const group = groupRef.current
    if (!group) return

    const rightBound = Math.max(0.5, viewport.width / 2 - BOUNCE_MARGIN_X)
    const leftBound = -rightBound
    const topBound = Math.max(0.5, viewport.height / 2 - BOUNCE_MARGIN_Y)
    const bottomBound = -topBound

    if (reducedMotion) {
      group.rotation.y = 0
      group.position.x = leftBound
      group.position.y = topBound
      return
    }

    group.rotation.y += delta * SPIN_SPEED

    const progress = Math.min(Math.max(window.scrollY / scrollMax.current, 0), 1)
    const raw = progress * LEGS_PER_PAGE
    const leg = Math.floor(raw)
    const frac = raw - leg
    const goingRight = leg % 2 === 0
    group.position.x = goingRight
      ? THREE.MathUtils.lerp(leftBound, rightBound, frac)
      : THREE.MathUtils.lerp(rightBound, leftBound, frac)

    // Cumulative descent (in px) across all fully-completed legs so far.
    let cumulativePx = 0
    for (let i = 0; i < leg; i++) cumulativePx += stepPxForLeg(i)

    const worldPerPixel = size.height > 0 ? viewport.height / size.height : 0.01
    const travelWorld = topBound - bottomBound
    const period = 2 * travelWorld
    const posInPeriod = travelWorld > 0 ? (cumulativePx * worldPerPixel) % period : 0
    const foldedDelta = posInPeriod <= travelWorld ? posInPeriod : period - posInPeriod
    group.position.y = topBound - foldedDelta
  })

  return (
    <group ref={groupRef}>
      {children}
    </group>
  )
}

export interface WormChainBackgroundProps {
  /** Overall intensity multiplier (0–1) for whoever embeds this. Defaults to 1 (base opacities are already low). */
  opacity?: number
}

/**
 * Passive (non-interactive), scroll-linked background element for the main
 * ecosystem scene: a solid, chunky, deep-blue chain (6 interlocking torus
 * links snaking through a serpentine curve, alternating perpendicular
 * orientation so they read as genuinely hooked together, unbroken and
 * continuous — no breaking/fragmenting) with a glowing cyan-blue "plexus"
 * of dots and connecting lines traced over each link's surface, plus sparse
 * static diagonal lines suggesting a network behind it — matching the
 * reference "digital chain" look rather than a thin wireframe treatment.
 *
 * Lives alongside CitadelFortress/OrbitalRing inside EcosystemScene's
 * shared <Canvas> (not its own isolated canvas) — renders raw scene content
 * meant to be placed directly inside another Canvas.
 */
export default function WormChainBackground({ opacity = 1 }: WormChainBackgroundProps) {
  const reducedMotion = usePrefersReducedMotion()
  const clampedOpacity = THREE.MathUtils.clamp(opacity, 0, 1)
  const links = useMemo(() => buildLinks(LINK_COUNT), [])

  return (
    <>
      <NetworkLines opacity={clampedOpacity} />
      <ScrollBounceSpinGroup reducedMotion={reducedMotion}>
        <ChainLinks links={links} opacity={clampedOpacity} />
        <ChainPlexus links={links} reducedMotion={reducedMotion} opacity={clampedOpacity} />
      </ScrollBounceSpinGroup>
    </>
  )
}
