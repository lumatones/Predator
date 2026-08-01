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
import './styles/onboarding-welcome.css'
// Holds the shared step-indicator styles (.onb-step*) used by OnboardingFlow
import './styles/onboarding-demo.css'
import './styles/onboarding-steps.css'
import './styles/onboarding-auth.css'
import './styles/components.css'
import './styles/components-buttons.css'
import './styles/components-glass-eye.css'
import './styles/components-music-player.css'
import './styles/components-settings.css'
import './styles/checker-core.css'
import './styles/checker-terminal.css'
import './styles/checker-modal.css'
import './styles/binary-triage.css'
import './styles/checker-groups.css'
import './styles/dashboard.css'
import './styles/dashboard-gauges.css'
import './styles/dashboard-processes.css'
import './styles/dashboard-stats.css'
import './styles/dashboard-stats-cards.css'
import './styles/dashboard-stats-chart.css'
import './styles/dashboard-stats-dirs.css'
import './styles/dashboard-stats-modes.css'
import './styles/dashboard-threat-map.css'
import './styles/onboarding-v2.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </React.StrictMode>,
)
