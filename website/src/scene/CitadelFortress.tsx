import { useRef } from 'react'
import { useFrame } from '@react-three/fiber'
import { Float } from '@react-three/drei'
import type { Mesh } from 'three'

export default function CitadelFortress() {
  const ref = useRef<Mesh>(null)

  useFrame(() => {
    if (ref.current) ref.current.rotation.y += 0.002
  })

  return (
    <Float speed={1.5} rotationIntensity={0.2} floatIntensity={0.3}>
      <mesh ref={ref}>
        <icosahedronGeometry args={[1.4, 1]} />
        <meshStandardMaterial
          wireframe
          color="#00f0ff"
          emissive="#00f0ff"
          emissiveIntensity={0.3}
          transparent
          opacity={0.85}
        />
      </mesh>
    </Float>
  )
}
