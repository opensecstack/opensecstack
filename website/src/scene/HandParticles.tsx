import { useRef, useMemo } from 'react'
import { useFrame } from '@react-three/fiber'
import * as THREE from 'three'
import type { HandState } from '../hooks/useHandTracking'
import { iconShapes } from './iconShapes'

/**
 * 1500 GPU-instanced particles that:
 *   - AMBIENT MODE: form programming language icon shapes, cycling every 4s
 *   - HAND MODE: respond to hand gestures (position, spread, openness)
 *
 * Each icon shape is a 2D point cloud. Particles morph between shapes
 * with staggered timing for a wave-dissolve effect.
 */

const PARTICLE_COUNT = 1500
const BASE_RADIUS = 2.5
const SHAPE_DURATION = 4        // seconds per icon shape
const MORPH_DURATION = 1.2      // transition time between shapes
const ICON_SCALE = 2.8          // scale multiplier for icon shapes

const TECH_COLORS = [
  new THREE.Color('#00ADD8'), // Go
  new THREE.Color('#CE422B'), // Rust
  new THREE.Color('#3776AB'), // Python
  new THREE.Color('#3178C6'), // TypeScript
  new THREE.Color('#7B42BC'), // Terraform
  new THREE.Color('#00f0ff'), // accent
]

interface Particle {
  // Shape morphing targets
  shapeTarget: THREE.Vector3
  nextShapeTarget: THREE.Vector3
  // Physics
  pos: THREE.Vector3
  vel: THREE.Vector3
  // Home position for ambient swirl (fibonacci sphere)
  home: THREE.Vector3
  // Per-particle config
  phase: number
  speed: number
  baseSize: number
  colorIdx: number
  morphDelay: number   // staggered morph timing (0-1)
}

// Pre-compute padded shape arrays (each exactly PARTICLE_COUNT points)
function padShape(shapeIdx: number): Array<[number, number]> {
  const raw = iconShapes[shapeIdx].points
  const result: Array<[number, number]> = []
  for (let i = 0; i < PARTICLE_COUNT; i++) {
    const src = raw[i % raw.length]
    // Add slight jitter for particles that reuse the same source point
    const jitter = i >= raw.length ? (Math.random() - 0.5) * 0.06 : 0
    result.push([src[0] + jitter, src[1] + jitter])
  }
  return result
}

const paddedShapes = iconShapes.map((_, i) => padShape(i))

interface Props {
  hand: HandState
}

export default function HandParticles({ hand }: Props) {
  const meshRef = useRef<THREE.InstancedMesh>(null)

  const smoothed = useRef({
    center: new THREE.Vector3(0, 0, 0),
    radius: BASE_RADIUS,
    scale: 1,
    handIntensity: 0,     // 0 = ambient (icon shapes), 1 = fully hand-controlled
    currentShape: 0,
    nextShape: 1,
    morphProgress: 0,
  })

  // Reusable objects (zero GC in hot loop)
  const _mat = useMemo(() => new THREE.Matrix4(), [])
  const _pos = useMemo(() => new THREE.Vector3(), [])
  const _scl = useMemo(() => new THREE.Vector3(), [])
  const _quat = useMemo(() => new THREE.Quaternion(), [])
  const _color = useMemo(() => new THREE.Color(), [])

  const particles = useMemo<Particle[]>(() => {
    const result: Particle[] = []
    const golden = (1 + Math.sqrt(5)) / 2
    for (let i = 0; i < PARTICLE_COUNT; i++) {
      // Fibonacci sphere for swirl home positions
      const theta = 2 * Math.PI * i / golden
      const phi = Math.acos(1 - 2 * (i + 0.5) / PARTICLE_COUNT)
      const hx = Math.sin(phi) * Math.cos(theta) * BASE_RADIUS
      const hy = Math.sin(phi) * Math.sin(theta) * BASE_RADIUS
      const hz = Math.cos(phi) * BASE_RADIUS

      // Initial shape target (first icon)
      const s0 = paddedShapes[0][i]
      const s1 = paddedShapes[1][i]

      result.push({
        shapeTarget: new THREE.Vector3(s0[0] * ICON_SCALE, s0[1] * ICON_SCALE, 0),
        nextShapeTarget: new THREE.Vector3(s1[0] * ICON_SCALE, s1[1] * ICON_SCALE, 0),
        pos: new THREE.Vector3(hx, hy, hz),
        vel: new THREE.Vector3(),
        home: new THREE.Vector3(hx, hy, hz),
        phase: Math.random() * Math.PI * 2,
        speed: 0.3 + Math.random() * 0.7,
        baseSize: 0.015 + Math.random() * 0.02,
        colorIdx: Math.floor(Math.random() * TECH_COLORS.length),
        morphDelay: Math.random(),  // 0-1 stagger
      })
    }
    return result
  }, [])

  // Set initial colors
  useMemo(() => {
    setTimeout(() => {
      if (!meshRef.current) return
      for (let i = 0; i < PARTICLE_COUNT; i++) {
        meshRef.current.setColorAt(i, TECH_COLORS[particles[i].colorIdx])
      }
      if (meshRef.current.instanceColor) meshRef.current.instanceColor.needsUpdate = true
    }, 0)
  }, [particles])

  useFrame(({ clock }) => {
    if (!meshRef.current) return
    const t = clock.getElapsedTime()
    const sm = smoothed.current

    // ── Determine mode: ambient (icons) vs hand-controlled ──

    const handActive = hand.active && hand.center !== null
    const targetHandIntensity = handActive ? 1 : 0
    sm.handIntensity += (targetHandIntensity - sm.handIntensity) * 0.06

    // ── Hand mode targets ──

    let handCenter = new THREE.Vector3(0, 0, 0)
    let handRadius = BASE_RADIUS
    let handScale = 1

    if (handActive && hand.center) {
      const nx = -(hand.center[0] - 0.5) * 12
      const ny = -(hand.center[1] - 0.5) * 8
      handCenter = new THREE.Vector3(nx, ny, 0)

      if (hand.handDistance !== null) {
        handRadius = 0.5 + hand.handDistance * 8
      }
      const avgOpenness = Math.max(hand.leftOpenness, hand.rightOpenness)
      handScale = 0.3 + avgOpenness * 1.5
      handRadius *= 0.5 + avgOpenness * 0.8
    }

    sm.center.lerp(handActive ? handCenter : new THREE.Vector3(0, 0, 0), 0.1)
    sm.radius += ((handActive ? handRadius : BASE_RADIUS) - sm.radius) * 0.08
    sm.scale += ((handActive ? handScale : 1) - sm.scale) * 0.1

    // ── Ambient: cycle through icon shapes ──

    const totalCycle = SHAPE_DURATION + MORPH_DURATION
    const cycleTime = t % (totalCycle * iconShapes.length)
    const currentShapeIdx = Math.floor(cycleTime / totalCycle) % iconShapes.length
    const nextShapeIdx = (currentShapeIdx + 1) % iconShapes.length
    const withinCycle = cycleTime - currentShapeIdx * totalCycle
    const morphT = Math.max(0, (withinCycle - SHAPE_DURATION) / MORPH_DURATION) // 0 = holding shape, 0→1 = morphing

    // Update shape targets when shape index changes
    if (currentShapeIdx !== sm.currentShape || nextShapeIdx !== sm.nextShape) {
      sm.currentShape = currentShapeIdx
      sm.nextShape = nextShapeIdx
      const currPts = paddedShapes[currentShapeIdx]
      const nextPts = paddedShapes[nextShapeIdx]
      for (let i = 0; i < PARTICLE_COUNT; i++) {
        particles[i].shapeTarget.set(currPts[i][0] * ICON_SCALE, currPts[i][1] * ICON_SCALE, 0)
        particles[i].nextShapeTarget.set(nextPts[i][0] * ICON_SCALE, nextPts[i][1] * ICON_SCALE, 0)
      }
    }

    // Current icon color for ambient mode
    const iconColor = new THREE.Color(iconShapes[currentShapeIdx].color)
    const nextIconColor = new THREE.Color(iconShapes[nextShapeIdx].color)

    // ── Update all particles ──

    for (let i = 0; i < PARTICLE_COUNT; i++) {
      const p = particles[i]

      // ── Ambient target: interpolate between current and next icon shape ──

      // Staggered morph: each particle starts morphing at a different time
      const staggeredT = Math.max(0, Math.min(1, (morphT - p.morphDelay * 0.5) / (1 - p.morphDelay * 0.5 + 0.01)))
      const eased = staggeredT * staggeredT * (3 - 2 * staggeredT) // smoothstep

      const ambientTarget = new THREE.Vector3().lerpVectors(
        p.shapeTarget,
        p.nextShapeTarget,
        eased,
      )

      // Add subtle z-depth variation to make it feel 3D even though shapes are 2D
      ambientTarget.z = Math.sin(p.phase + t * 0.3) * 0.4

      // ── Hand target: orbit around hand center ──

      const orbitAngle = t * p.speed * 0.3 + p.phase
      const handTarget = p.home.clone()
        .applyAxisAngle(new THREE.Vector3(0, 1, 0), orbitAngle * 0.2)
        .multiplyScalar(sm.radius / BASE_RADIUS)
        .add(sm.center)

      // ── Blend between ambient and hand mode ──

      const blendedTarget = new THREE.Vector3().lerpVectors(
        ambientTarget,
        handTarget,
        sm.handIntensity,
      )

      // Spring physics
      const toTarget = blendedTarget.clone().sub(p.pos)
      p.vel.add(toTarget.multiplyScalar(0.04))
      p.vel.multiplyScalar(0.9)
      p.pos.add(p.vel)

      // ── Write instance matrix ──

      _pos.copy(p.pos)
      const distFromTarget = p.pos.distanceTo(blendedTarget)
      const sizeBoost = 1 + distFromTarget * 0.3 // particles get bigger while in flight
      const s = p.baseSize * sm.scale * sizeBoost
      _scl.set(s, s, s)
      _mat.compose(_pos, _quat, _scl)
      meshRef.current!.setMatrixAt(i, _mat)

      // ── Color: blend between icon color and tech color ──

      const ambientColor = _color.clone().lerpColors(iconColor, nextIconColor, eased)
      const techColor = TECH_COLORS[p.colorIdx]
      const finalColor = _color.lerpColors(ambientColor, techColor, sm.handIntensity)

      // Brightness pulse
      const pulse = 0.7 + Math.sin(t * 2 + p.phase) * 0.3
      finalColor.multiplyScalar(pulse)

      meshRef.current!.setColorAt(i, finalColor)
    }

    meshRef.current.instanceMatrix.needsUpdate = true
    if (meshRef.current.instanceColor) meshRef.current.instanceColor.needsUpdate = true
  })

  return (
    <instancedMesh ref={meshRef} args={[undefined, undefined, PARTICLE_COUNT]} frustumCulled={false}>
      <sphereGeometry args={[1, 6, 6]} />
      <meshBasicMaterial
        transparent
        opacity={0.85}
        depthWrite={false}
        blending={THREE.AdditiveBlending}
        toneMapped={false}
      />
    </instancedMesh>
  )
}
