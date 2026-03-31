import { lazy, Suspense } from 'react'
import { useWebGL } from './hooks/useWebGL'
import Navbar from './components/Navbar'
import Footer from './components/Footer'
import HeroSection from './sections/HeroSection'
import PlatformsSection from './sections/PlatformsSection'
import APIGuardSection from './sections/APIGuardSection'
import NIS2CompassSection from './sections/NIS2CompassSection'
import CitadelSection from './sections/CitadelSection'
import SDKSection from './sections/SDKSection'
import RoadmapSection from './sections/RoadmapSection'

const EcosystemScene = lazy(() => import('./scene/EcosystemScene'))

export default function App() {
  const webgl = useWebGL()

  return (
    <>
      {webgl && (
        <Suspense fallback={null}>
          <EcosystemScene />
        </Suspense>
      )}

      <div className="scroll-content">
        <Navbar />
        <HeroSection />
        <PlatformsSection />
        <APIGuardSection />
        <NIS2CompassSection />
        <CitadelSection />
        <SDKSection />
        <RoadmapSection />
        <Footer />
      </div>
    </>
  )
}
