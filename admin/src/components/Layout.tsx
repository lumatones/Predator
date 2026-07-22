import { NavLink } from 'react-router-dom'
import { useAuth } from '../App'
import { ReactNode } from 'react'

interface LayoutProps {
  children: ReactNode
}

export default function Layout({ children }: LayoutProps) {
  const { auth, logout } = useAuth()

  return (
    <div className="layout">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-header">
          <NavLink to="/" className="sidebar-logo">
            <svg viewBox="0 0 28 28" fill="none">
              <path d="M14 2L2 14L14 26L26 14L14 2Z" fill="url(#sg)" opacity="0.15"/>
              <path d="M14 6L6 14L14 22L22 14L14 6Z" fill="url(#sg)" opacity="0.3"/>
              <path d="M14 10L10 14L14 18L18 14L14 10Z" fill="url(#sg)"/>
              <defs>
                <linearGradient id="sg" x1="2" y1="2" x2="26" y2="26">
                  <stop stopColor="#ff4444"/>
                  <stop offset="1" stopColor="#ff6b35"/>
                </linearGradient>
              </defs>
            </svg>
            <h2>Predator</h2>
            <span>admin</span>
          </NavLink>
        </div>

        <nav className="sidebar-nav">
          <NavLink to="/" end className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="3" width="7" height="7" rx="1"/>
              <rect x="14" y="3" width="7" height="7" rx="1"/>
              <rect x="3" y="14" width="7" height="7" rx="1"/>
              <rect x="14" y="14" width="7" height="7" rx="1"/>
            </svg>
            <span>Dashboard</span>
          </NavLink>

          <NavLink to="/pending" className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M9 11l3 3L22 4"/>
              <path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h7"/>
            </svg>
            <span>Запросы</span>
          </NavLink>

          <NavLink to="/tokens" className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
              <path d="M7 11V7a5 5 0 0110 0v4"/>
            </svg>
            <span>Токены</span>
          </NavLink>

          <NavLink to="/history" className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10"/>
              <polyline points="12 6 12 12 16 14"/>
            </svg>
            <span>История</span>
          </NavLink>
        </nav>

        <div className="sidebar-footer">
          <div className="sidebar-user">
            <div className="sidebar-user-avatar">
              {auth?.admin.username.charAt(0).toUpperCase()}
            </div>
            <div className="sidebar-user-info">
              <div className="sidebar-user-name">{auth?.admin.username}</div>
              <div className="sidebar-user-role">{auth?.admin.role}</div>
            </div>
            <button className="sidebar-logout" onClick={logout} title="Выйти">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/>
                <polyline points="16 17 21 12 16 7"/>
                <line x1="21" y1="12" x2="9" y2="12"/>
              </svg>
            </button>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="main-content">
        {children}
      </main>
    </div>
  )
}
