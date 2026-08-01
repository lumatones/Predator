import { Link, useLocation } from 'react-router-dom'
import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

const NAV_ITEMS = [
  { path: '/', label: 'Главная' },
  { path: '/players', label: 'База данных' },
  { path: '/news', label: 'Новости' },
]

export default function Navbar() {
  const location = useLocation()
  const [mobileOpen, setMobileOpen] = useState(false)

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 bg-predator-bg/80 backdrop-blur-xl border-b border-predator-border">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <Link to="/" className="flex items-center gap-3 group">
            <div className="w-8 h-8 rounded-lg bg-predator-accent/20 flex items-center justify-center group-hover:bg-predator-accent/30 transition-colors">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#22c55e" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
            </div>
            <span className="text-lg font-bold tracking-tight">
              <span className="text-predator-accent">Predator</span>
              <span className="text-predator-muted ml-1.5 text-sm font-normal hidden sm:inline">Anti-Cheat</span>
            </span>
          </Link>

          {/* Desktop Nav */}
          <div className="hidden md:flex items-center gap-1">
            {NAV_ITEMS.map(item => (
              <Link
                key={item.path}
                to={item.path}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
                  location.pathname === item.path
                    ? 'text-predator-accent bg-predator-accent/10'
                    : 'text-predator-muted hover:text-predator-text hover:bg-predator-card'
                }`}
              >
                {item.label}
              </Link>
            ))}
          </div>

          {/* Auth */}
          <div className="hidden md:flex items-center gap-3">
            <Link
              to="/login"
              className="px-4 py-2 rounded-lg text-sm font-medium text-predator-muted hover:text-predator-text hover:bg-predator-card transition-all"
            >
              Войти
            </Link>
            <Link
              to="/login"
              className="px-4 py-2 rounded-lg text-sm font-semibold bg-predator-accent text-black hover:bg-predator-accent/90 transition-all"
            >
              Регистрация
            </Link>
          </div>

          {/* Mobile toggle */}
          <button
            className="md:hidden p-2 rounded-lg text-predator-muted hover:text-predator-text hover:bg-predator-card"
            onClick={() => setMobileOpen(o => !o)}
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              {mobileOpen
                ? <><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></>
                : <><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="18" x2="21" y2="18"/></>
              }
            </svg>
          </button>
        </div>
      </div>

      {/* Mobile menu */}
      <AnimatePresence>
        {mobileOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="md:hidden border-t border-predator-border bg-predator-bg/95 backdrop-blur-xl overflow-hidden"
          >
            <div className="px-4 py-3 space-y-1">
              {NAV_ITEMS.map(item => (
                <Link
                  key={item.path}
                  to={item.path}
                  onClick={() => setMobileOpen(false)}
                  className={`block px-4 py-2.5 rounded-lg text-sm font-medium transition-all ${
                    location.pathname === item.path
                      ? 'text-predator-accent bg-predator-accent/10'
                      : 'text-predator-muted hover:text-predator-text hover:bg-predator-card'
                  }`}
                >
                  {item.label}
                </Link>
              ))}
              <div className="pt-2 border-t border-predator-border flex gap-2">
                <Link to="/login" onClick={() => setMobileOpen(false)} className="flex-1 text-center px-4 py-2.5 rounded-lg text-sm font-medium text-predator-muted hover:text-predator-text hover:bg-predator-card transition-all">
                  Войти
                </Link>
                <Link to="/login" onClick={() => setMobileOpen(false)} className="flex-1 text-center px-4 py-2.5 rounded-lg text-sm font-semibold bg-predator-accent text-black hover:bg-predator-accent/90 transition-all">
                  Регистрация
                </Link>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </nav>
  )
}
