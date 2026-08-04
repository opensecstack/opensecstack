import { useRef, useMemo } from 'react'
import { useFrame, useThree, useLoader } from '@react-three/fiber'
import * as THREE from 'three'

/**
 * 3D interactive icon particles for the 5 core languages/tools.
 * Each icon is a textured sprite (always faces camera) with physics:
 *   - gentle orbit around a cluster center
 *   - mouse attraction: icons drift toward cursor when nearby
 *   - mouse repulsion ring: pushed away if too close
 *   - spring return to orbit when mouse leaves
 *
 * Multiple copies of each icon create a cloud of ~30 particles.
 */

interface TechDef {
  label: string
  icon: string       // path in public/icons/
  color: string
  glowColor: string
}

const techs: TechDef[] = [
  { label: 'Go',         icon: '/icons/go.svg',         color: '#00ADD8', glowColor: '#00ADD8' },
  { label: 'Rust',       icon: '/icons/rust.svg',       color: '#CE422B', glowColor: '#CE422B' },
  { label: 'Python',     icon: '/icons/python.svg',     color: '#3776AB', glowColor: '#FFD43B' },
  { label: 'TypeScript', icon: '/icons/typescript.svg', color: '#3178C6', glowColor: '#3178C6' },
  { label: 'Terraform',  icon: '/icons/terraform.svg',  color: '#7B42BC', glowColor: '#5C4EE5' },
]

// How many copies of each icon
const COPIES_PER_ICON = 6
const TOTAL = techs.length * COPIES_PER_ICON

// Physics tuning
const CLUSTER_CENTER = new THREE.Vector3(5.5, -0.5, -1)
const ORBIT_RADIUS = 2.8
const MOUSE_ATTRACT_RADIUS = 5
const MOUSE_REPEL_RADIUS = 1.5
const ATTRACT_STRENGTH = 0.015
const REPEL_STRENGTH = 0.06
const RETURN_STRENGTH = 0.006
const DRIFT_SPEED = 0.25
const DAMPING = 0.94
const SPRITE_SIZE = 0.55

interface Particle {
  techIdx: number
  homePos: THREE.Vector3
  pos: THREE.Vector3
  vel: THREE.Vector3
  phase: number
  orbitSpeed: number
  orbitRadius: number
  yOffset: number
  size: number
}

export default function TechParticles() {
  const groupRef = useRef<THREE.Group>(null)
  const { camera } = useThree()

  // Reusable scratch objects — avoids allocating new THREE.Vector3 instances
  // for every particle on every frame (30 particles * 60fps adds up fast).
  const scratch = useRef({
    ndcMouse: new THREE.Vector3(),
    dir: new THREE.Vector3(),
    mouseWorld: new THREE.Vector3(),
    driftHome: new THREE.Vector3(),
    toMouse: new THREE.Vector3(),
    toHome: new THREE.Vector3(),
    scaleTarget: new THREE.Vector3(),
  }).current

  // Load all icon textures
  const textures = useLoader(
    THREE.TextureLoader,
    techs.map(t => t.icon),
  )

  // Initialize particle state
  const particles = useMemo<Particle[]>(() => {
    const result: Particle[] = []
    for (let i = 0; i < techs.length; i++) {
      for (let c = 0; c < COPIES_PER_ICON; c++) {
        const angle = ((i * COPIES_PER_ICON + c) / TOTAL) * Math.PI * 2 + (Math.random() - 0.5) * 0.5
        const r = ORBIT_RADIUS * (0.6 + Math.random() * 0.8)
        const y = (Math.random() - 0.5) * 2.5
        const home = new THREE.Vector3(
          CLUSTER_CENTER.x + Math.cos(angle) * r,
          CLUSTER_CENTER.y + y,
          CLUSTER_CENTER.z + Math.sin(angle) * r,
        )
        result.push({
          techIdx: i,
          homePos: home.clone(),
          pos: home.clone(),
          vel: new THREE.Vector3(),
          phase: Math.random() * Math.PI * 2,
          orbitSpeed: 0.08 + Math.random() * 0.12,
          orbitRadius: r,
          yOffset: y,
          size: SPRITE_SIZE * (0.7 + Math.random() * 0.6),
        })
      }
    }
    return result
  }, [])

  useFrame(({ clock, pointer }, delta) => {
    if (!groupRef.current) return
    const t = clock.getElapsedTime()
    // Physics constants below were tuned assuming a 60fps frame step;
    // scale per-frame velocity changes by (delta * 60) so the spring/drag
    // feel stays consistent at other frame rates instead of looking
    // stiffer/softer than intended.
    const frameScale = delta * 60

    // Project mouse into 3D at cluster z-plane
    const { ndcMouse, dir, mouseWorld, driftHome, toMouse, toHome, scaleTarget } = scratch
    ndcMouse.set(pointer.x, pointer.y, 0.5).unproject(camera)
    dir.copy(ndcMouse).sub(camera.position).normalize()
    const planeDist = (CLUSTER_CENTER.z - camera.position.z) / dir.z
    mouseWorld.copy(camera.position).add(dir.multiplyScalar(planeDist))

    const children = groupRef.current.children
    for (let i = 0; i < TOTAL; i++) {
      const p = particles[i]
      const sprite = children[i] as THREE.Sprite
      if (!sprite) continue

      // Orbit drift: home position slowly orbits around cluster center
      const orbitAngle = t * p.orbitSpeed + p.phase
      driftHome.set(
        CLUSTER_CENTER.x + Math.cos(orbitAngle) * p.orbitRadius,
        CLUSTER_CENTER.y + p.yOffset + Math.sin(t * DRIFT_SPEED + p.phase) * 0.3,
        CLUSTER_CENTER.z + Math.sin(orbitAngle) * p.orbitRadius,
      )

      // Mouse interaction
      toMouse.copy(mouseWorld).sub(p.pos)
      const mouseDist = toMouse.length()

      if (mouseDist < MOUSE_REPEL_RADIUS) {
        // Too close — push away
        const force = (1 - mouseDist / MOUSE_REPEL_RADIUS) * REPEL_STRENGTH
        p.vel.add(toMouse.normalize().multiplyScalar(-force * frameScale))
      } else if (mouseDist < MOUSE_ATTRACT_RADIUS) {
        // In attraction zone — gently pull toward mouse
        const factor = 1 - (mouseDist - MOUSE_REPEL_RADIUS) / (MOUSE_ATTRACT_RADIUS - MOUSE_REPEL_RADIUS)
        p.vel.add(toMouse.normalize().multiplyScalar(factor * ATTRACT_STRENGTH * frameScale))
      }

      // Spring back toward drifting home
      toHome.copy(driftHome).sub(p.pos)
      p.vel.add(toHome.multiplyScalar(RETURN_STRENGTH * frameScale))

      // Damping — exponential so decay-per-second stays constant across frame rates
      p.vel.multiplyScalar(Math.pow(DAMPING, frameScale))

      // Integrate
      p.pos.add(p.vel)

      // Apply to sprite
      sprite.position.copy(p.pos)

      // Scale pulse on mouse proximity
      const proximity = Math.max(0, 1 - mouseDist / MOUSE_ATTRACT_RADIUS)
      const target = p.size * (1 + proximity * 0.5)
      scaleTarget.set(target, target, 1)
      sprite.scale.lerp(scaleTarget, 0.08)

      // Opacity: brighter when near mouse
      const mat = sprite.material as THREE.SpriteMaterial
      mat.opacity = 0.5 + proximity * 0.5
    }
  })

  return (
    <group ref={groupRef}>
      {particles.map((p, i) => {
        const tex = textures[p.techIdx]
        return (
          <sprite key={i} position={p.pos.toArray()} scale={[p.size, p.size, 1]}>
            <spriteMaterial
              map={tex}
              transparent
              opacity={0.6}
              depthWrite={false}
              blending={THREE.AdditiveBlending}
            />
          </sprite>
        )
      })}
    </group>
  )
}
