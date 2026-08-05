import { useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
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

interface DriftGroupProps {
  reducedMotion: boolean
  basePosition: [number, number, number]
  children: ReactNode
}

/**
 * Wraps the chain in a very subtle, bounded sway (not a full continuous
 * spin) — barely perceptible ambient motion rather than an
 * attention-grabbing animation. Uses delta-scaled accumulation so the sway
 * speed is frame-rate independent, and is skipped entirely (leaving the
 * group fully static at its base transform) when reduced motion is
 * requested.
 */
function DriftGroup({ reducedMotion, basePosition, children }: DriftGroupProps) {
  const groupRef = useRef<THREE.Group>(null)
  const phaseRef = useRef(0)

  useFrame((_state, delta) => {
    if (reducedMotion) return
    const group = groupRef.current
    if (!group) return
    phaseRef.current += delta * 0.15
    group.rotation.y = Math.sin(phaseRef.current) * 0.06
    group.position.y = basePosition[1] + Math.sin(phaseRef.current * 0.6) * 0.08
  })

  return (
    <group ref={groupRef} position={basePosition}>
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

      <DriftGroup reducedMotion={reducedMotion} basePosition={[-2.2, 0, 0]}>
        <ChainLinks links={links} opacity={opacity} />
        <ChainParticles links={links} reducedMotion={reducedMotion} opacity={opacity} />
      </DriftGroup>
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
 * continuous — no breaking/fragmenting) drifting almost imperceptibly,
 * with small glowing "star" particles scattered across a subset of its
 * links and sparse static diagonal lines suggesting a network behind it.
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
