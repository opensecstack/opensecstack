import { lazy, Suspense, useEffect, useRef, useState } from 'react'
import { Helmet } from 'react-helmet-async'
import ErrorBoundary from '../components/ErrorBoundary'
import { useWebGL } from '../hooks/useWebGL'
import { useThemeToggle } from '../hooks/useThemeToggle'
import Navbar from '../components/Navbar'
import Footer from '../components/Footer'
import HeroSection from '../sections/HeroSection'
import PlatformsSection from '../sections/PlatformsSection'
import ShowcaseSection from '../sections/ShowcaseSection'
import APIGuardSection from '../sections/APIGuardSection'
import NIS2CompassSection from '../sections/NIS2CompassSection'
import CitadelSection from '../sections/CitadelSection'
import SDKSection from '../sections/SDKSection'
import RoadmapSection from '../sections/RoadmapSection'
import RunixSection from '../sections/RunixSection'
import ThreatFlowSection from '../sections/ThreatFlowSection'
import IRFlowSection from '../sections/IRFlowSection'
import OpenScrubSection from '../sections/OpenScrubSection'
import CyberPathSection from '../sections/CyberPathSection'
import SecureLabSection from '../sections/SecureLabSection'
import OpenCSIRTSection from '../sections/OpenCSIRTSection'
import VertGuardSection from '../sections/VertGuardSection'
import SINSection from '../sections/SINSection'
import SinauthSection from '../sections/SinauthSection'

const EcosystemScene = lazy(() => import('../scene/EcosystemScene'))

/**
 * Defers mounting the (large, decorative) 3D scene until the browser is
 * idle, so it never competes with critical first-paint work. Falls back to
 * a short timeout in browsers without requestIdleCallback (e.g. Safari).
 */
function useDeferredMount() {
  const [ready, setReady] = useState(false)
  const idleId = useRef<number | null>(null)
  const timeoutId = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    const win = window as Window & {
      requestIdleCallback?: (cb: () => void) => number
      cancelIdleCallback?: (id: number) => void
    }

    if (typeof win.requestIdleCallback === 'function') {
      idleId.current = win.requestIdleCallback(() => setReady(true))
    } else {
      timeoutId.current = setTimeout(() => setReady(true), 200)
    }

    return () => {
      if (idleId.current !== null && typeof win.cancelIdleCallback === 'function') {
        win.cancelIdleCallback(idleId.current)
      }
      if (timeoutId.current !== null) {
        clearTimeout(timeoutId.current)
      }
    }
  }, [])

  return ready
}

export default function HomePage() {
  const webgl = useWebGL()
  const deferredReady = useDeferredMount()
  useThemeToggle() // initialize theme (body class + localStorage) on mount

  return (
    <>
      <Helmet>
        <title>SIN — Security Intelligence Network</title>
        <meta
          name="description"
          content="SIN — Security Intelligence Network. Open-source cybersecurity and compliance platform for the EU Digital Decade. API security, NIS2 compliance, and immutable governance."
        />
        <link rel="canonical" href="https://opensecstack.github.io/opensecstack/" />
        <meta property="og:url" content="https://opensecstack.github.io/opensecstack/" />
        <meta property="og:title" content="SIN — Security Intelligence Network" />
        <meta
          property="og:description"
          content="APIGuard, NIS2 Compass, and CITADEL governance engine — open-source tools for EU Digital Decade compliance."
        />
      </Helmet>
      {webgl && deferredReady && (
        // Isolate WebGL / Three.js failures so a driver issue or runtime
        // error in the 3D scene never takes down the whole page. Falling
        // back to null leaves the static content intact. Mounting is
        // deferred to idle time (see useDeferredMount) so this large,
        // decorative chunk never blocks first paint.
        <ErrorBoundary scope="ecosystem-scene">
          <Suspense fallback={null}>
            <EcosystemScene />
          </Suspense>
        </ErrorBoundary>
      )}
      <div className="scroll-content">
        <Navbar />
        <main id="main">
          <HeroSection />
          <PlatformsSection />
          <ShowcaseSection />
          <APIGuardSection />
          <NIS2CompassSection />
          <CitadelSection />
          <RunixSection />
          <IRFlowSection />
          <ThreatFlowSection />
          <OpenScrubSection />
          <CyberPathSection />
          <SecureLabSection />
          <OpenCSIRTSection />
          <VertGuardSection />
          <SinauthSection />
          <SINSection />
          <SDKSection />
          <RoadmapSection />
        </main>
        <Footer />
      </div>
    </>
  )
}
