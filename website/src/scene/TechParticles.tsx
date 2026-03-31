import { useRef, useMemo, useCallback } from 'react'
import { useFrame, useThree } from '@react-three/fiber'
import { Html } from '@react-three/drei'
import * as THREE from 'three'

/**
 * Floating language/tech icon particles that drift gently and
 * repel away from the mouse pointer in 3D space.
 */

interface TechIcon {
  label: string
  symbol: string
  color: string
}

const techs: TechIcon[] = [
  { label: 'Go',         symbol: 'Go',   color: '#00ADD8' },
  { label: 'Rust',       symbol: 'Rs',   color: '#CE422B' },
  { label: 'Python',     symbol: 'Py',   color: '#3776AB' },
  { label: 'TypeScript', symbol: 'TS',   color: '#3178C6' },
  { label: 'React',      symbol: 'Re',   color: '#61DAFB' },
  { label: 'PostgreSQL', symbol: 'Pg',   color: '#4169E1' },
  { label: 'Redis',      symbol: 'Rd',   color: '#DC382D' },
  { label: 'Docker',     symbol: 'Dk',   color: '#2496ED' },
  { label: 'gRPC',       symbol: 'gR',   color: '#244C5A' },
  { label: 'OpenAPI',    symbol: 'OA',   color: '#6BA539' },
  { label: 'SARIF',      symbol: 'SF',   color: '#8B5CF6' },
  { label: 'Ed25519',    symbol: 'Ed',   color: '#F59E0B' },
  { label: 'BLAKE3',     symbol: 'B3',   color: '#10B981' },
  { label: 'SHA-256',    symbol: '#2',   color: '#06B6D4' },
  { label: 'Vite',       symbol: 'Vi',   color: '#646CFF' },
  { label: 'Flask',      symbol: 'Fl',   color: '#FFFFFF' },
  { label: 'WORM',       symbol: 'WM',   color: '#00F0FF' },
  { label: 'CVSS',       symbol: 'CV',   color: '#EF4444' },
]

const PARTICLE_COUNT = techs.length
const SPREAD = 18
const MOUSE_REPEL_RADIUS = 3
const MOUSE_REPEL_STRENGTH = 0.04
const DRIFT_SPEED = 0.15
const RETURN_SPEED = 0.008

interface ParticleState {
  homePos: THREE.Vector3
  currentPos: THREE.Vector3
  velocity: THREE.Vector3
  phase: number
}

export default function TechParticles() {
  const groupRef = useRef<THREE.Group>(null)
  const mouse3D = useRef(new THREE.Vector3(999, 999, 999))
  const { camera } = useThree()

  const particles = useMemo<ParticleState[]>(() => {
    return techs.map((_, i) => {
      // Distribute in a wide shell around the scene
      const theta = (i / PARTICLE_COUNT) * Math.PI * 2 + (Math.random() - 0.5) * 0.8
      const phi = Math.acos(2 * Math.random() - 1)
      const r = SPREAD * 0.4 + Math.random() * SPREAD * 0.6
      const x = r * Math.sin(phi) * Math.cos(theta)
      const y = (Math.random() - 0.5) * SPREAD * 0.5
      const z = r * Math.sin(phi) * Math.sin(theta)

      return {
        homePos: new THREE.Vector3(x, y, z),
        currentPos: new THREE.Vector3(x, y, z),
        velocity: new THREE.Vector3(),
        phase: Math.random() * Math.PI * 2,
      }
    })
  }, [])

  const onPointerMove = useCallback((e: THREE.Event & { point: THREE.Vector3 }) => {
    mouse3D.current.copy(e.point)
  }, [])

  useFrame(({ clock, pointer }) => {
    if (!groupRef.current) return
    const t = clock.getElapsedTime()

    // Project mouse into 3D at z=0 plane
    const mouseNDC = new THREE.Vector3(pointer.x, pointer.y, 0.5)
    mouseNDC.unproject(camera)
    const dir = mouseNDC.sub(camera.position).normalize()
    const dist = -camera.position.z / dir.z
    const mouseWorld = camera.position.clone().add(dir.multiplyScalar(dist))

    const children = groupRef.current.children
    for (let i = 0; i < PARTICLE_COUNT; i++) {
      const p = particles[i]
      const child = children[i]
      if (!child) continue

      // Gentle drift around home position
      const driftX = Math.sin(t * DRIFT_SPEED + p.phase) * 0.5
      const driftY = Math.cos(t * DRIFT_SPEED * 0.7 + p.phase * 1.3) * 0.3
      const target = p.homePos.clone().add(new THREE.Vector3(driftX, driftY, 0))

      // Mouse repulsion
      const toMouse = p.currentPos.clone().sub(mouseWorld)
      const mouseDist = toMouse.length()
      if (mouseDist < MOUSE_REPEL_RADIUS) {
        const force = (1 - mouseDist / MOUSE_REPEL_RADIUS) * MOUSE_REPEL_STRENGTH
        p.velocity.add(toMouse.normalize().multiplyScalar(force))
      }

      // Return to home + drift
      p.velocity.add(target.clone().sub(p.currentPos).multiplyScalar(RETURN_SPEED))

      // Damping
      p.velocity.multiplyScalar(0.95)

      // Apply
      p.currentPos.add(p.velocity)
      child.position.copy(p.currentPos)

      // Slow rotation
      child.rotation.y = t * 0.2 + p.phase
    }
  })

  return (
    <group ref={groupRef}>
      {techs.map((tech, i) => (
        <group key={tech.label} position={particles[i].homePos.toArray()}>
          <Html
            center
            distanceFactor={15}
            style={{ pointerEvents: 'none', userSelect: 'none' }}
          >
            <div style={{
              width: 36,
              height: 36,
              borderRadius: 8,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              background: `${tech.color}18`,
              border: `1px solid ${tech.color}40`,
              color: tech.color,
              fontSize: 12,
              fontWeight: 700,
              fontFamily: 'JetBrains Mono, monospace',
              letterSpacing: '-0.02em',
              boxShadow: `0 0 12px ${tech.color}22`,
              opacity: 0.7,
            }}
            title={tech.label}
            >
              {tech.symbol}
            </div>
          </Html>
        </group>
      ))}
      {/* Invisible plane to capture pointer move for mouse position */}
      <mesh visible={false} onPointerMove={onPointerMove}>
        <planeGeometry args={[100, 100]} />
        <meshBasicMaterial transparent opacity={0} />
      </mesh>
    </group>
  )
}
