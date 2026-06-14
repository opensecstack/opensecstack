import { Suspense } from 'react'
import { Canvas } from '@react-three/fiber'
import { Stars } from '@react-three/drei'
import { EffectComposer, Bloom, Vignette } from '@react-three/postprocessing'
import MobileDevice from './platforms/MobileDevice'

export default function MobileScene() {
  return (
    <div className="scene-container">
      <Canvas
        camera={{ position: [0, 0, 5], fov: 50 }}
        dpr={[1, 1.5]}
        gl={{ antialias: true, alpha: true }}
      >
        <ambientLight intensity={0.1} />
        <pointLight position={[4, 4, 4]} intensity={0.3} color="#10b981" />
        <pointLight position={[-4, -2, -4]} intensity={0.15} color="#3b82f6" />

        <Suspense fallback={null}>
          <Stars radius={80} depth={40} count={1500} factor={3} saturation={0} fade speed={0.3} />
          <group position={[3, 0, 0]} scale={[0.6, 0.6, 0.6]}>
            <MobileDevice />
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
