import { Routes, Route, Navigate } from 'react-router-dom'
import { useState, useEffect, createContext, useContext } from 'react'
import Layout from './components/Layout'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Pending from './pages/Pending'
import Tokens from './pages/Tokens'
import History from './pages/History'

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

  const login = (token: string, admin: AuthState['admin']) => {
    const data = { token, admin }
    localStorage.setItem('predator_admin', JSON.stringify(data))
    setAuth(data)
  }

  const logout = () => {
    localStorage.removeItem('predator_admin')
    setAuth(null)
  }

  if (!auth) {
    return (
      <div className="login-wrapper">
        <div className="orb-1" />
        <div className="orb-2" />
        <div className="orb-3" />
        <Login onLogin={login} />
      </div>
    )
  }

  return (
    <AuthContext.Provider value={{ auth, login, logout }}>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/pending" element={<Pending />} />
          <Route path="/tokens" element={<Tokens />} />
          <Route path="/history" element={<History />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>
    </AuthContext.Provider>
  )
}
