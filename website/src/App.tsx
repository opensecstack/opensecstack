import { lazy, Suspense } from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
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
import CitadelOSSection from './sections/CitadelOSSection'

const EcosystemScene = lazy(() => import('./scene/EcosystemScene'))
const CitadelOSPage = lazy(() => import('./pages/CitadelOSPage'))
const CitadelOSMobilePage = lazy(() => import('./pages/CitadelOSMobilePage'))

function HomePage() {
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
        <CitadelOSSection />
        <SDKSection />
        <RoadmapSection />
        <Footer />
      </div>
    </>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/citadelos" element={
          <Suspense fallback={null}>
            <CitadelOSPage />
          </Suspense>
        } />
        <Route path="/citadelos/mobile" element={
          <Suspense fallback={null}>
            <CitadelOSMobilePage />
          </Suspense>
        } />
      </Routes>
    </BrowserRouter>
  )
}
