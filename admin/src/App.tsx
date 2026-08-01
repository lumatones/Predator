import { Routes, Route, Navigate } from 'react-router-dom'
import { useState, createContext, useContext, useCallback } from 'react'
import Layout from './components/Layout'
import ParticleBackground from './components/ParticleBackground'
import Login from './pages/Login'
import HomePage from './pages/HomePage'
import Dashboard from './pages/Dashboard'
import Pending from './pages/Pending'
import Tokens from './pages/Tokens'
import History from './pages/History'
import SuspiciousHashes from './pages/SuspiciousHashes'
import SafeFiles from './pages/SafeFiles'
import { useSessionTimeout } from './hooks/useSessionTimeout'
import SessionTimeoutModal from './components/SessionTimeoutModal'
import { useNavigationShortcuts } from './hooks/useKeyboardShortcuts'
import KeyboardShortcutsHelp from './components/KeyboardShortcutsHelp'

interface AuthState {
  token: string
  admin: { id: number; username: string; role: string }
}

interface AuthContextType {
  auth: AuthState | null
  login: (token: string, admin: AuthState['admin']) => void
  logout: () => void
}

export const AuthContext = createContext<AuthContextType>({
  auth: null,
  login: () => {},
  logout: () => {},
})

export const useAuth = () => useContext(AuthContext)

export default function App() {
  const [auth, setAuth] = useState<AuthState | null>(() => {
    const stored = localStorage.getItem('predator_admin')
    return stored ? JSON.parse(stored) : null
  })

  const [shortcutsHelpOpen, setShortcutsHelpOpen] = useState(false)

  const login = (token: string, admin: AuthState['admin']) => {
    const data = { token, admin }
    localStorage.setItem('predator_admin', JSON.stringify(data))
    setAuth(data)
  }

  const logout = useCallback(() => {
    localStorage.removeItem('predator_admin')
    setAuth(null)
  }, [])

  // Session timeout — auto-logout after 30 min inactivity
  const { showWarning, remaining } = useSessionTimeout(!!auth, logout)

  // Keyboard shortcuts — navigation, help toggle
  useNavigationShortcuts(() => setShortcutsHelpOpen(prev => !prev), !!auth)

  if (!auth) {
    return (
      <div className="login-wrapper">
        <ParticleBackground density={80} opacity={0.3} speed={0.5} linkOpacity={0.1} />
        <div className="login-scan-line" />
        <Login onLogin={login} />
      </div>
    )
  }

  return (
    <AuthContext.Provider value={{ auth, login, logout }}>
      <Layout>
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/pending" element={<Pending />} />
          <Route path="/tokens" element={<Tokens />} />
          <Route path="/history" element={<History />} />
          <Route path="/hashes" element={<SuspiciousHashes />} />
          <Route path="/safe-files" element={<SafeFiles />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>

      {/* Keyboard shortcuts help modal */}
      <KeyboardShortcutsHelp
        open={shortcutsHelpOpen}
        onClose={() => setShortcutsHelpOpen(false)}
      />

      {/* Session timeout warning modal */}
      {showWarning && (
        <SessionTimeoutModal
          show={showWarning}
          remaining={remaining}
          onExtend={() => {/* handled by activity listener */}}
          onLogout={logout}
        />
      )}
    </AuthContext.Provider>
  )
}
