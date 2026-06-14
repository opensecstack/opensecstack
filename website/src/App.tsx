import { lazy, Suspense } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import ScrollToTop from './components/ScrollToTop'
import ErrorBoundary from './components/ErrorBoundary'
import { useWebGL } from './hooks/useWebGL'
import { useThemeToggle } from './hooks/useThemeToggle'
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
import ThreatFlowSection from './sections/ThreatFlowSection'
import IRFlowSection from './sections/IRFlowSection'
import OpenScrubSection from './sections/OpenScrubSection'
import CyberPathSection from './sections/CyberPathSection'
import SecureLabSection from './sections/SecureLabSection'
import OpenCSIRTSection from './sections/OpenCSIRTSection'
import VertGuardSection from './sections/VertGuardSection'
import SINSection from './sections/SINSection'
import SinauthSection from './sections/SinauthSection'

const EcosystemScene = lazy(() => import('./scene/EcosystemScene'))
const CitadelOSPage = lazy(() => import('./pages/CitadelOSPage'))
const CitadelOSMobilePage = lazy(() => import('./pages/CitadelOSMobilePage'))
const NotFoundPage = lazy(() => import('./pages/NotFoundPage'))
const AuthCallbackPage = lazy(() => import('./pages/AuthCallbackPage'))

const IntroPage = lazy(() => import('./pages/docs/IntroPage'))
const QuickStartPage = lazy(() => import('./pages/docs/QuickStartPage'))
const InstallationPage = lazy(() => import('./pages/docs/InstallationPage'))
const ArchitecturePage = lazy(() => import('./pages/docs/ArchitecturePage'))
const ContractsPage = lazy(() => import('./pages/docs/ContractsPage'))
const PlatformsPage = lazy(() => import('./pages/docs/PlatformsPage'))
const IdentityPage = lazy(() => import('./pages/docs/IdentityPage'))
const GovernancePage = lazy(() => import('./pages/docs/GovernancePage'))
const DeploymentPage = lazy(() => import('./pages/docs/DeploymentPage'))
const SecurityPage = lazy(() => import('./pages/docs/SecurityPage'))

const ApiGuardPage = lazy(() => import('./pages/docs/platforms/ApiGuardPage'))
const Nis2CompassPage = lazy(() => import('./pages/docs/platforms/Nis2CompassPage'))
const IrflowPage = lazy(() => import('./pages/docs/platforms/IrflowPage'))
const ThreatflowPage = lazy(() => import('./pages/docs/platforms/ThreatflowPage'))
const OpenScrubPage = lazy(() => import('./pages/docs/platforms/OpenScrubPage'))
const CyberPathPage = lazy(() => import('./pages/docs/platforms/CyberPathPage'))
const SecureLabPage = lazy(() => import('./pages/docs/platforms/SecureLabPage'))
const OpenCsirtPage = lazy(() => import('./pages/docs/platforms/OpenCsirtPage'))
const VertGuardPage = lazy(() => import('./pages/docs/platforms/VertGuardPage'))
const CommunityPage = lazy(() => import('./pages/docs/platforms/CommunityPage'))

const LocalDevPage = lazy(() => import('./pages/docs/LocalDevPage'))
const TdsPage = lazy(() => import('./pages/docs/TdsPage'))
const CitadelIntegrationPage = lazy(() => import('./pages/docs/CitadelIntegrationPage'))
const WebhooksPage = lazy(() => import('./pages/docs/WebhooksPage'))
const Nis2Page = lazy(() => import('./pages/docs/Nis2Page'))
const ReleasesPage = lazy(() => import('./pages/docs/ReleasesPage'))
const SdkGoPage = lazy(() => import('./pages/docs/SdkGoPage'))
const SdkPythonPage = lazy(() => import('./pages/docs/SdkPythonPage'))
const SdkTypeScriptPage = lazy(() => import('./pages/docs/SdkTypeScriptPage'))
const SdkRustPage = lazy(() => import('./pages/docs/SdkRustPage'))

const MarshalPage = lazy(() => import('./pages/docs/citadel/MarshalPage'))
const WormChainPage = lazy(() => import('./pages/docs/citadel/WormChainPage'))
const SodPage = lazy(() => import('./pages/docs/citadel/SodPage'))
const AugurVigilPage = lazy(() => import('./pages/docs/citadel/AugurVigilPage'))
const EvidencePage = lazy(() => import('./pages/docs/citadel/EvidencePage'))

function HomePage() {
  const webgl = useWebGL()
  useThemeToggle() // initialize theme (body class + localStorage) on mount

  return (
    <>
      {webgl && (
        // Isolate WebGL / Three.js failures so a driver issue or runtime
        // error in the 3D scene never takes down the whole page. Falling
        // back to null leaves the static content intact.
        <ErrorBoundary scope="ecosystem-scene">
          <Suspense fallback={null}>
            <EcosystemScene />
          </Suspense>
        </ErrorBoundary>
      )}
      <div className="scroll-content">
        <Navbar />
        <HeroSection />
        <PlatformsSection />
        <APIGuardSection />
        <NIS2CompassSection />
        <CitadelSection />
        <CitadelOSSection />
        <ThreatFlowSection />
        <IRFlowSection />
        <OpenScrubSection />
        <CyberPathSection />
        <SecureLabSection />
        <OpenCSIRTSection />
        <VertGuardSection />
        <SinauthSection />
        <SINSection />
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
      <ScrollToTop />
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
        <Route path="/auth/callback" element={
          <Suspense fallback={null}>
            <AuthCallbackPage />
          </Suspense>
        } />
        <Route path="/docs" element={<Navigate to="/docs/intro" replace />} />
        <Route path="/docs/intro"        element={<Suspense fallback={null}><IntroPage /></Suspense>} />
        <Route path="/docs/quickstart"   element={<Suspense fallback={null}><QuickStartPage /></Suspense>} />
        <Route path="/docs/installation" element={<Suspense fallback={null}><InstallationPage /></Suspense>} />
        <Route path="/docs/architecture" element={<Suspense fallback={null}><ArchitecturePage /></Suspense>} />
        <Route path="/docs/contracts"    element={<Suspense fallback={null}><ContractsPage /></Suspense>} />
        <Route path="/docs/platforms"    element={<Suspense fallback={null}><PlatformsPage /></Suspense>} />
        <Route path="/docs/identity"     element={<Suspense fallback={null}><IdentityPage /></Suspense>} />
        <Route path="/docs/governance"   element={<Suspense fallback={null}><GovernancePage /></Suspense>} />
        <Route path="/docs/deployment"   element={<Suspense fallback={null}><DeploymentPage /></Suspense>} />
        <Route path="/docs/security"     element={<Suspense fallback={null}><SecurityPage /></Suspense>} />
        <Route path="/docs/platforms/apiguard"    element={<Suspense fallback={null}><ApiGuardPage /></Suspense>} />
        <Route path="/docs/platforms/nis2compass" element={<Suspense fallback={null}><Nis2CompassPage /></Suspense>} />
        <Route path="/docs/platforms/irflow"      element={<Suspense fallback={null}><IrflowPage /></Suspense>} />
        <Route path="/docs/platforms/threatflow"  element={<Suspense fallback={null}><ThreatflowPage /></Suspense>} />
        <Route path="/docs/platforms/openscrub"   element={<Suspense fallback={null}><OpenScrubPage /></Suspense>} />
        <Route path="/docs/platforms/cyberpath"   element={<Suspense fallback={null}><CyberPathPage /></Suspense>} />
        <Route path="/docs/platforms/securelab"   element={<Suspense fallback={null}><SecureLabPage /></Suspense>} />
        <Route path="/docs/platforms/opencsirt"   element={<Suspense fallback={null}><OpenCsirtPage /></Suspense>} />
        <Route path="/docs/platforms/vertguard"   element={<Suspense fallback={null}><VertGuardPage /></Suspense>} />
        <Route path="/docs/platforms/community"   element={<Suspense fallback={null}><CommunityPage /></Suspense>} />
        <Route path="/docs/local-dev"          element={<Suspense fallback={null}><LocalDevPage /></Suspense>} />
        <Route path="/docs/tds"                element={<Suspense fallback={null}><TdsPage /></Suspense>} />
        <Route path="/docs/citadel-integration" element={<Suspense fallback={null}><CitadelIntegrationPage /></Suspense>} />
        <Route path="/docs/webhooks"           element={<Suspense fallback={null}><WebhooksPage /></Suspense>} />
        <Route path="/docs/nis2"               element={<Suspense fallback={null}><Nis2Page /></Suspense>} />
        <Route path="/docs/releases"           element={<Suspense fallback={null}><ReleasesPage /></Suspense>} />
        <Route path="/docs/sdk/go"             element={<Suspense fallback={null}><SdkGoPage /></Suspense>} />
        <Route path="/docs/sdk/python"         element={<Suspense fallback={null}><SdkPythonPage /></Suspense>} />
        <Route path="/docs/sdk/typescript"     element={<Suspense fallback={null}><SdkTypeScriptPage /></Suspense>} />
        <Route path="/docs/sdk/rust"           element={<Suspense fallback={null}><SdkRustPage /></Suspense>} />
        <Route path="/docs/citadel/marshal"     element={<Suspense fallback={null}><MarshalPage /></Suspense>} />
        <Route path="/docs/citadel/worm"        element={<Suspense fallback={null}><WormChainPage /></Suspense>} />
        <Route path="/docs/citadel/sod"         element={<Suspense fallback={null}><SodPage /></Suspense>} />
        <Route path="/docs/citadel/augur-vigil" element={<Suspense fallback={null}><AugurVigilPage /></Suspense>} />
        <Route path="/docs/citadel/evidence"    element={<Suspense fallback={null}><EvidencePage /></Suspense>} />
        {/* SPA 404: unknown paths render inside the app rather than falling
            through to the static public/404.html, which would lose theme
            and language state and break the browser back button. */}
        <Route path="*" element={
          <Suspense fallback={null}>
            <NotFoundPage />
          </Suspense>
        } />
      </Routes>
    </BrowserRouter>
  )
}
