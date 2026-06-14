import { Suspense } from 'react'
import { Canvas } from '@react-three/fiber'
import { Stars } from '@react-three/drei'
import { EffectComposer, Bloom, Vignette } from '@react-three/postprocessing'
import DesktopKernel from './platforms/DesktopKernel'

export default function DesktopScene() {
  return (
    <div className="scene-container">
      <Canvas
        camera={{ position: [0, 0, 6], fov: 50 }}
        dpr={[1, 1.5]}
        gl={{ antialias: true, alpha: true }}
      >
        <ambientLight intensity={0.1} />
        <pointLight position={[5, 5, 5]} intensity={0.3} color="#00f0ff" />
        <pointLight position={[-5, -3, -5]} intensity={0.15} color="#7c3aed" />

        <Suspense fallback={null}>
          <Stars radius={80} depth={40} count={1500} factor={3} saturation={0} fade speed={0.3} />
          <group position={[3, 0, 0]} scale={[0.6, 0.6, 0.6]}>
            <DesktopKernel />
          </group>
          <EffectComposer>
            <Bloom luminanceThreshold={0.4} luminanceSmoothing={0.9} intensity={0.5} />
            <Vignette eskil={false} offset={0.1} darkness={0.5} />
          </EffectComposer>
        </Suspense>
      </Canvas>
    </div>
  )
}
