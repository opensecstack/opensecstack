import { useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { Canvas, useFrame, useThree } from '@react-three/fiber'
import * as THREE from 'three'

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

// Shared accent palette (see src/data/platforms.ts / WormChainVisual.tsx) plus
// a muted silver/gray for the wireframe chain itself, since this is a
// background texture and shouldn't compete with the foreground accent hues.
const SILVER = '#9aa5b8'
const SILVER_GLOW = '#e2e8f0'
const CYAN = '#00f0ff'
const VIOLET = '#7c3aed'
const MAGENTA = '#e040fb'

const LINK_COUNT = 12
const TORUS_RADIUS = 0.55
const TORUS_TUBE = 0.14
// Deliberately low segment counts for a faceted/angular low-poly look
// rather than a smooth ring.
const RADIAL_SEGMENTS = 6
const TUBULAR_SEGMENTS = 9

type LinkTint = 'silver' | 'cyan' | 'violet'

interface LinkData {
  position: THREE.Vector3
  quaternion: THREE.Quaternion
  tint: LinkTint
}

/**
 * A loose diagonal curve the chain follows, running from upper area down to
 * lower area while receding slightly in depth — matches the reference
 * image's diagonal composition. Kept as a pure function of t so tangents can
 * be derived by sampling nearby points.
 */
function pathPoint(t: number): THREE.Vector3 {
  const x = -1.2 + t * 2.4
  const y = 2.6 - t * 5.2
  const z = -1.5 - Math.sin(t * Math.PI) * 1.2
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

    const tintRoll = i % 5
    const tint: LinkTint = tintRoll === 2 ? 'cyan' : tintRoll === 4 ? 'violet' : 'silver'

    links.push({
      position: pos,
      quaternion: dummy.quaternion.clone(),
      tint,
    })
  }

  return links
}

const SAMPLE_ANGLES: Array<[number, number]> = [
  [0.2, 0.6],
  [1.4, -0.5],
  [2.6, 0.4],
  [3.8, -0.6],
  [5.0, 0.5],
]

const PARTICLE_PALETTE = [CYAN, VIOLET, MAGENTA, CYAN, SILVER_GLOW]

/**
 * Scatters glowing "star" points at a subset of the chain's approximate
 * wireframe vertex positions (every other link, a handful of surface points
 * each) by evaluating the torus parametric surface directly — cheaper than
 * reading back real geometry vertices and keeps the point count modest
 * (~30) since this is decorative background, not a focal effect.
 */
function buildParticleAttributes(links: LinkData[]): { positions: Float32Array; colors: Float32Array } {
  const selected = links.filter((_, i) => i % 2 === 0)
  const positions = new Float32Array(selected.length * SAMPLE_ANGLES.length * 3)
  const colors = new Float32Array(selected.length * SAMPLE_ANGLES.length * 3)
  const local = new THREE.Vector3()
  const tint = new THREE.Color()
  let vi = 0
  let ci = 0
  let paletteIndex = 0

  for (const link of selected) {
    for (const [u, v] of SAMPLE_ANGLES) {
      const r = TORUS_RADIUS + TORUS_TUBE * Math.cos(v)
      local.set(r * Math.cos(u), r * Math.sin(u), TORUS_TUBE * Math.sin(v))
      local.applyQuaternion(link.quaternion)
      local.add(link.position)
      positions[vi++] = local.x
      positions[vi++] = local.y
      positions[vi++] = local.z

      tint.set(PARTICLE_PALETTE[paletteIndex % PARTICLE_PALETTE.length])
      paletteIndex++
      colors[ci++] = tint.r
      colors[ci++] = tint.g
      colors[ci++] = tint.b
    }
  }

  return { positions, colors }
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

/** The faceted wireframe chain links themselves — one shared geometry, three shared tint materials. */
function ChainLinks({ links, opacity }: ChainLinksProps) {
  const geometry = useMemo(
    () => new THREE.TorusGeometry(TORUS_RADIUS, TORUS_TUBE, RADIAL_SEGMENTS, TUBULAR_SEGMENTS),
    [],
  )
  const materials = useMemo(
    () => ({
      silver: new THREE.MeshBasicMaterial({
        color: SILVER,
        wireframe: true,
        transparent: true,
        opacity: 0.28 * opacity,
        toneMapped: false,
      }),
      cyan: new THREE.MeshBasicMaterial({
        color: CYAN,
        wireframe: true,
        transparent: true,
        opacity: 0.32 * opacity,
        toneMapped: false,
      }),
      violet: new THREE.MeshBasicMaterial({
        color: VIOLET,
        wireframe: true,
        transparent: true,
        opacity: 0.32 * opacity,
        toneMapped: false,
      }),
    }),
    [opacity],
  )

  // Dispose geometry only on unmount (it's stable across opacity changes)
  // and dispose each material set only when a new set replaces it.
  useEffect(() => () => geometry.dispose(), [geometry])
  useEffect(() => () => {
    materials.silver.dispose()
    materials.cyan.dispose()
    materials.violet.dispose()
  }, [materials])

  return (
    <>
      {links.map((link, i) => (
        <mesh key={i} position={link.position} quaternion={link.quaternion} geometry={geometry} material={materials[link.tint]} />
      ))}
    </>
  )
}

interface ChainParticlesProps {
  links: LinkData[]
  reducedMotion: boolean
  opacity: number
}

/** Small glowing "star" points scattered across the wireframe, pulsing very subtly. */
function ChainParticles({ links, reducedMotion, opacity }: ChainParticlesProps) {
  const { positions, colors } = useMemo(() => buildParticleAttributes(links), [links])
  const materialRef = useRef<THREE.PointsMaterial>(null)
  const phaseRef = useRef(0)
  const baseOpacity = 0.85 * opacity

  useFrame((_state, delta) => {
    const mat = materialRef.current
    if (!mat) return
    if (reducedMotion) {
      mat.opacity = baseOpacity
      mat.size = 0.07
      return
    }
    phaseRef.current += delta * 0.6
    const pulse = 0.5 + 0.5 * Math.sin(phaseRef.current)
    mat.opacity = baseOpacity * (0.65 + 0.35 * pulse)
    mat.size = 0.05 + 0.03 * pulse
  })

  return (
    <points>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" count={positions.length / 3} array={positions} itemSize={3} />
        <bufferAttribute attach="attributes-color" count={colors.length / 3} array={colors} itemSize={3} />
      </bufferGeometry>
      <pointsMaterial
        ref={materialRef}
        vertexColors
        size={0.06}
        sizeAttenuation
        transparent
        opacity={baseOpacity}
        blending={THREE.AdditiveBlending}
        depthWrite={false}
        toneMapped={false}
      />
    </points>
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
      <lineBasicMaterial color={SILVER} transparent opacity={0.12 * opacity} />
    </lineSegments>
  )
}

interface BounceSpinGroupProps {
  reducedMotion: boolean
  children: ReactNode
}

/** Continuous rotation speed around the Y axis, in radians/second. */
const SPIN_SPEED = 0.6
/** Horizontal sweep speed, in world units/second. */
const MOVE_SPEED = 1.8
/** Half-extent margins (world units) so the chain's own visual bulk stays
 * on-screen at the bounds rather than its center touching the literal edge. */
const BOUNCE_MARGIN_X = 1.6
const BOUNCE_MARGIN_Y = 2.2
/** Vertical step applied at each left/right collision, randomized within
 * this pixel range (converted to world units) per the requested "50-100px" motion. */
const MIN_STEP_PX = 50
const MAX_STEP_PX = 100

interface BounceState {
  x: number
  y: number
  dirX: 1 | -1
  /** -1 while stepping toward the bottom on each bounce, +1 while stepping back toward the top. */
  dirY: 1 | -1
  initialized: boolean
}

/**
 * Continuously spins the chain (Y-axis rotation, never stops) while bouncing
 * it around the visible panel like a boustrophedon sweep: start at the
 * top-left corner, sweep right, collide with the right edge, step downward
 * by a randomized 50-100px, sweep left, collide with the left edge, step
 * down again — repeating until the bottom edge is reached, at which point
 * the vertical stepping direction reverses and the same left-right sweep
 * climbs back to the top, forever. Frame-rate independent (delta-scaled),
 * and frozen entirely (holding a static top-left pose, no rotation) when
 * reduced motion is requested.
 */
function BounceSpinGroup({ reducedMotion, children }: BounceSpinGroupProps) {
  const groupRef = useRef<THREE.Group>(null)
  const { viewport, size } = useThree()
  const stateRef = useRef<BounceState>({ x: 0, y: 0, dirX: 1, dirY: -1, initialized: false })

  useFrame((_state, delta) => {
    const group = groupRef.current
    if (!group) return

    const rightBound = Math.max(0.5, viewport.width / 2 - BOUNCE_MARGIN_X)
    const leftBound = -rightBound
    const topBound = Math.max(0.5, viewport.height / 2 - BOUNCE_MARGIN_Y)
    const bottomBound = -topBound
    const s = stateRef.current

    if (!s.initialized) {
      s.x = leftBound
      s.y = topBound
      s.dirX = 1
      s.dirY = -1
      s.initialized = true
    }

    if (reducedMotion) {
      // Hold a static, still-legible top-left pose — no spin, no sweep.
      group.rotation.y = 0
      group.position.x = leftBound
      group.position.y = topBound
      return
    }

    group.rotation.y += delta * SPIN_SPEED

    s.x += s.dirX * MOVE_SPEED * delta

    const worldPerPixel = size.height > 0 ? viewport.height / size.height : 0.01
    if (s.x >= rightBound) {
      s.x = rightBound
      s.dirX = -1
      const stepWorld = (MIN_STEP_PX + Math.random() * (MAX_STEP_PX - MIN_STEP_PX)) * worldPerPixel
      s.y += s.dirY * stepWorld
    } else if (s.x <= leftBound) {
      s.x = leftBound
      s.dirX = 1
      const stepWorld = (MIN_STEP_PX + Math.random() * (MAX_STEP_PX - MIN_STEP_PX)) * worldPerPixel
      s.y += s.dirY * stepWorld
    }

    if (s.y <= bottomBound) {
      s.y = bottomBound
      s.dirY = 1
    } else if (s.y >= topBound) {
      s.y = topBound
      s.dirY = -1
    }

    group.position.x = s.x
    group.position.y = s.y
  })

  return (
    <group ref={groupRef}>
      {children}
    </group>
  )
}

interface SceneProps {
  reducedMotion: boolean
  opacity: number
}

function Scene({ reducedMotion, opacity }: SceneProps) {
  const links = useMemo(() => buildLinks(LINK_COUNT), [])

  return (
    <>
      <ambientLight intensity={0.35} />
      <pointLight position={[-3, 2, 4]} intensity={0.35} color={CYAN} />

      <NetworkLines opacity={opacity} />

      <BounceSpinGroup reducedMotion={reducedMotion}>
        <ChainLinks links={links} opacity={opacity} />
        <ChainParticles links={links} reducedMotion={reducedMotion} opacity={opacity} />
      </BounceSpinGroup>
    </>
  )
}

export interface WormChainBackgroundProps {
  className?: string
  /** Overall intensity multiplier (0–1) for whoever embeds this behind page content. Defaults to a subtle 1 (base opacities are already low). */
  opacity?: number
}

/**
 * Passive, non-interactive background layer: a low-poly, wireframe,
 * faceted chain (12 interlocking torus links, alternating perpendicular
 * orientation so they read as genuinely hooked together, unbroken and
 * continuous — no breaking/fragmenting) that spins continuously while
 * bouncing corner-to-corner across the panel (top-left → right edge →
 * left edge → ... stepping 50-100px down each bounce → bottom edge →
 * reverses to climb back to the top the same way, forever), with small
 * glowing "star" particles scattered across a subset of its links and
 * sparse static diagonal lines suggesting a network behind it.
 *
 * Designed to sit behind DOM content (own transparent <Canvas>, absolute
 * inset positioning, pointer-events disabled) at low cost: no
 * postprocessing, no Html tooltips, shared geometry/materials across links,
 * and no per-frame object allocation.
 */
export default function WormChainBackground({ className, opacity = 1 }: WormChainBackgroundProps) {
  const reducedMotion = usePrefersReducedMotion()
  const clampedOpacity = THREE.MathUtils.clamp(opacity, 0, 1)

  return (
    <div
      className={className}
      style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', pointerEvents: 'none' }}
    >
      <Canvas
        camera={{ position: [0, 0, 9], fov: 55 }}
        dpr={[1, 1.5]}
        gl={{ antialias: true, alpha: true }}
        style={{ background: 'transparent' }}
      >
        <Scene reducedMotion={reducedMotion} opacity={clampedOpacity} />
      </Canvas>
    </div>
  )
}
