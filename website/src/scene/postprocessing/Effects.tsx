import { EffectComposer, Bloom, Vignette } from '@react-three/postprocessing'

export default function Effects() {
  return (
    <EffectComposer>
      <Bloom luminanceThreshold={0.6} luminanceSmoothing={0.9} intensity={0.4} />
      <Vignette eskil={false} offset={0.1} darkness={0.5} />
    </EffectComposer>
  )
}
