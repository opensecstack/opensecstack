import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { useEffect } from 'react'

function ScrollToTop() {
  const { pathname, hash } = useLocation()
  useEffect(() => {
    if (hash) {
      const scrollToHash = () => {
        const el = document.getElementById(hash.slice(1))
        if (el) { el.scrollIntoView({ behavior: 'smooth' }); return true }
        return false
      }
      if (scrollToHash()) return
      const t = setTimeout(scrollToHash, 100)
      return () => clearTimeout(t)
    }
    window.scrollTo(0, 0)
  }, [pathname, hash])
  return null
}
import HomePage from './pages/HomePage'
import AuthCallbackPage from './pages/AuthCallbackPage'
import IntroPage from './pages/docs/IntroPage'
import QuickStartPage from './pages/docs/QuickStartPage'
import InstallationPage from './pages/docs/InstallationPage'
import ConfigPage from './pages/docs/ConfigPage'
import DatabasePage from './pages/docs/DatabasePage'
import PKCEPage from './pages/docs/PKCEPage'
import PopupSSOPage from './pages/docs/PopupSSOPage'
import SDKGoPage from './pages/docs/SDKGoPage'
import SDKTSPage from './pages/docs/SDKTSPage'
import SDKPage from './pages/docs/SDKPage'
import APIAuthPage from './pages/docs/APIAuthPage'
import APIAdminPage from './pages/docs/APIAdminPage'

export default function App() {
  return (
    <BrowserRouter>
      <ScrollToTop />
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/auth/callback" element={<AuthCallbackPage />} />

        <Route path="/docs" element={<Navigate to="/docs/intro" replace />} />
        <Route path="/docs/intro"        element={<IntroPage />} />
        <Route path="/docs/quickstart"   element={<QuickStartPage />} />
        <Route path="/docs/installation" element={<InstallationPage />} />
        <Route path="/docs/config"       element={<ConfigPage />} />
        <Route path="/docs/database"     element={<DatabasePage />} />
        <Route path="/docs/pkce"         element={<PKCEPage />} />
        <Route path="/docs/popup-sso"    element={<PopupSSOPage />} />
        <Route path="/docs/sdk-go"       element={<SDKGoPage />} />
        <Route path="/docs/sdk-ts"       element={<SDKTSPage />} />
        <Route path="/docs/sdk"          element={<SDKPage />} />
        <Route path="/docs/api-auth"     element={<APIAuthPage />} />
        <Route path="/docs/api-admin"    element={<APIAdminPage />} />

        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
