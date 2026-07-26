import { NavLink, useLocation } from 'react-router-dom'
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion'
import { LayoutDashboard, ClipboardCheck, Key, History, Activity, LogOut } from 'lucide-react'
import { useAuth } from '../App'
import { ReactNode, useState, useEffect } from 'react'
import ParticleBackground from './ParticleBackground'
import CommandPalette from './CommandPalette'
import { Menu, X, Command, Search } from 'lucide-react'

interface LayoutProps {
  children: ReactNode
}

export default function Layout({ children }: LayoutProps) {
  const { auth, logout } = useAuth()
  const { pathname } = useLocation()
  const [isMobileOpen, setIsMobileOpen] = useState(false)
  const [commandOpen, setCommandOpen] = useState(false)
  const reducedMotion = useReducedMotion()

  useEffect(() => {
    setIsMobileOpen(false)
  }, [pathname])

  useEffect(() => {
    document.body.style.overflow = isMobileOpen ? 'hidden' : ''
    return () => { document.body.style.overflow = '' }
  }, [isMobileOpen])

  return (
    <div className="layout">
      <div className="mobile-header">
        <button
          className="mobile-menu-btn"
          onClick={() => setIsMobileOpen(prev => !prev)}
          aria-label="Открыть меню"
        >
          <Menu size={20} />
        </button>
        <span className="mobile-title">Predator Admin</span>
        <button
          className="mobile-menu-btn"
          onClick={() => setCommandOpen(true)}
          aria-label="Открыть командную палитру"
          title="Командная палитра (Ctrl+K / Cmd+K)"
        >
          <Command size={20} />
        </button>
      </div>

      <div
        className={`sidebar-overlay ${isMobileOpen ? 'open' : ''}`}
        onClick={() => setIsMobileOpen(false)}
      />

      {/* Sidebar */}
      <aside className={`sidebar ${isMobileOpen ? 'open' : ''}`}>
        <div className="sidebar-header">
          <button
            className="command-palette-trigger"
            onClick={() => setCommandOpen(true)}
            aria-label="Открыть командную палитру"
            title="Командная палитра (Ctrl+K / Cmd+K)"
          >
            <Search size={16} />
            <span>Поиск</span>
            <kbd className="command-kbd">⌘K</kbd>
          </button>
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
          <NavLink to="/" end className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`} title="Dashboard">
            <LayoutDashboard size={18} />
            <span>Dashboard</span>
          </NavLink>

          <NavLink to="/pending" className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`} title="Запросы на доступ">
            <ClipboardCheck size={18} />
            <span>Запросы</span>
          </NavLink>

          <NavLink to="/tokens" className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`} title="Управление токенами">
            <Key size={18} />
            <span>Токены</span>
          </NavLink>

          <NavLink to="/history" className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`} title="История сканирований">
            <History size={18} />
            <span>История</span>
          </NavLink>

          <NavLink to="/hashes" className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`} title="Подозрительные сигнатуры">
            <Activity size={18} />
            <span>Сигнатуры</span>
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
              <LogOut size={18} />
            </button>
          </div>
        </div>
        <div className="sidebar-footer-mobile">
          <button
            className="mobile-close-btn"
            onClick={() => setIsMobileOpen(false)}
            aria-label="Закрыть меню"
          >
            <X size={20} />
            <span>Закрыть</span>
          </button>
        </div>
      </aside>

      <CommandPalette open={commandOpen} onOpenChange={setCommandOpen} withTrigger={false} />

      {/* Main content */}
      <div className="layout-bg">
        <ParticleBackground density={30} opacity={0.15} speed={0.3} linkOpacity={0.02} links={false} />
      </div>
      <AnimatePresence mode="wait">
        <motion.main
          key={pathname}
          className="main-content"
          initial={{ opacity: 0, y: reducedMotion ? 0 : 8 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: reducedMotion ? 0 : -8 }}
          transition={{
            duration: reducedMotion ? 0 : 0.25,
            ease: [0.16, 1, 0.3, 1]
          }}
        >
          {children}
        </motion.main>
      </AnimatePresence>
    </div>
  )
}
