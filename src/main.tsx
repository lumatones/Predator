import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import ErrorBoundary from './components/ErrorBoundary'
import '@fontsource/inter/400.css'
import '@fontsource/inter/500.css'
import '@fontsource/inter/600.css'
import '@fontsource/inter/700.css'
import '@fontsource/instrument-serif/400.css'
import '@fontsource/instrument-serif/400-italic.css'
import './styles/tokens.css'
import './styles/layout.css'
import './styles/onboarding.css'
import './styles/components.css'
import './styles/components-buttons.css'
import './styles/components-glass-eye.css'
import './styles/components-music-player.css'
import './styles/components-settings.css'
import './styles/checker-core.css'
import './styles/checker-terminal.css'
import './styles/checker-modal.css'
import './styles/checker-groups.css'
import './styles/dashboard.css'
import './styles/onboarding-v2.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </React.StrictMode>,
)
