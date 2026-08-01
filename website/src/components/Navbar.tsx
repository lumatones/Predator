import { Link, useLocation } from 'react-router-dom'
import { useState } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import { Menu, X, ArrowUpRight } from 'lucide-react'

const NAV_ITEMS = [
  { path: '/', label: 'Обзор' },
  { path: '/players', label: 'Реестр игроков' },
  { path: '/news', label: 'Обновления' },
]

export default function Navbar() {
  const location = useLocation()
  const [mobileOpen, setMobileOpen] = useState(false)

  return (
    <nav className="fixed left-0 right-0 top-0 z-50 border-b border-white/[0.08] bg-predator-bg/85 backdrop-blur-xl">
      <div className="mx-auto flex h-[76px] max-w-6xl items-center justify-between px-4 sm:px-6 lg:px-8">
        <Link to="/" className="flex items-center gap-3" aria-label="Predator — главная">
          <span className="grid h-9 w-9 place-items-center rounded-full bg-predator-accent text-sm font-bold text-predator-bg shadow-lg shadow-predator-accent/10">P</span>
          <span className="text-base font-semibold tracking-[-0.03em] text-predator-text">Predator</span>
        </Link>

        <div className="hidden items-center gap-1 rounded-full border border-white/[0.08] bg-white/[0.025] p-1 md:flex">
          {NAV_ITEMS.map(item => {
            const active = location.pathname === item.path
            return (
              <Link key={item.path} to={item.path} className={`relative rounded-full px-4 py-2 text-sm transition-colors ${active ? 'text-predator-text' : 'text-predator-muted hover:text-predator-text'}`}>
                {active && <motion.span layoutId="navbar-active-pill" className="absolute inset-0 rounded-full bg-white/[0.1]" transition={{ type: 'spring', stiffness: 320, damping: 28 }} />}
                <span className="relative z-10">{item.label}</span>
              </Link>
            )
          })}
        </div>

        <div className="hidden items-center gap-5 md:flex">
          <span className="text-xs text-predator-muted">Античит для GTA 5 RP</span>
          <Link to="/login" className="inline-flex items-center gap-2 rounded-full border border-white/[0.1] px-4 py-2 text-sm font-medium text-predator-text transition-colors hover:border-predator-accent/50 hover:text-predator-accent">
            Личный кабинет <ArrowUpRight size={14} />
          </Link>
        </div>

        <button type="button" aria-label={mobileOpen ? 'Закрыть меню' : 'Открыть меню'} aria-expanded={mobileOpen} className="rounded-full border border-white/[0.1] p-2.5 text-predator-muted hover:border-predator-accent/50 hover:text-predator-text md:hidden" onClick={() => setMobileOpen(open => !open)}>
          {mobileOpen ? <X size={18} /> : <Menu size={18} />}
        </button>
      </div>

      <AnimatePresence>
        {mobileOpen && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden border-t border-white/[0.08] bg-predator-bg/95 backdrop-blur-xl md:hidden">
            <div className="space-y-2 px-4 py-4">
              {NAV_ITEMS.map(item => (
                <Link key={item.path} to={item.path} onClick={() => setMobileOpen(false)} className={`block rounded-2xl px-4 py-3 text-sm transition-colors ${location.pathname === item.path ? 'bg-white/[0.09] text-predator-text' : 'text-predator-muted hover:bg-white/[0.04] hover:text-predator-text'}`}>
                  {item.label}
                </Link>
              ))}
              <Link to="/login" onClick={() => setMobileOpen(false)} className="mt-3 block rounded-full border border-white/[0.12] px-4 py-3 text-center text-sm font-medium text-predator-text">
                Личный кабинет
              </Link>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </nav>
  )
}
