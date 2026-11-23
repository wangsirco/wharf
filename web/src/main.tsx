import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { applyTheme, getTheme } from './lib/theme'
import { ErrorBoundary } from './components/error-boundary'

applyTheme(getTheme())

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ErrorBoundary><App /></ErrorBoundary>
  </StrictMode>,
)

// no service worker: the manifest alone makes the panel installable, and an old worker
// (≤ 0.18) could keep showing its offline page on devices that distrust the certificate
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.getRegistrations().then((rs) => rs.forEach((r) => r.unregister())).catch(() => {})
}

// a reload after a panel update (error-boundary.tsx) happens once; a page that stays up clears the flag
setTimeout(() => sessionStorage.removeItem('owp-chunk-reload'), 15000)
