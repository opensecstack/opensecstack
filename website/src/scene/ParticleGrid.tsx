import { Stars, Grid } from '@react-three/drei'

export default function ParticleGrid() {
  return (
    <>
      <Stars radius={100} depth={50} count={2500} factor={4} saturation={0} fade speed={0.4} />
      <Grid
        infiniteGrid
        fadeDistance={30}
        cellSize={0.6}
        sectionSize={3}
        sectionColor="#1a1a3e"
        cellColor="#0a0a2e"
        position={[0, -3, 0]}
      />
    </>
  )
}
