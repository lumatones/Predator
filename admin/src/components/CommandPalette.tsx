import { useEffect, useRef, useState, useMemo, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import {
  LayoutDashboard,
  ClipboardCheck,
  Key,
  History,
  Activity,
  LogOut,
  Search,
  Command
} from 'lucide-react'
import { useAuth } from '../App'
import { useFocusTrap } from '../hooks/useFocusTrap'
import './CommandPalette.css'

interface CommandPaletteProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  withTrigger?: boolean
}

export interface CommandItem {
  id: string
  label: string
  icon: React.ReactNode
  action: () => void
  keywords?: string[]
}

function useCommands(): CommandItem[] {
  const navigate = useNavigate()
  const { logout } = useAuth()

  return useMemo<CommandItem[]>(() => {
    const items: CommandItem[] = [
      {
        id: 'nav-dashboard',
        label: 'Dashboard',
        icon: <LayoutDashboard size={18} />,
        action: () => navigate('/'),
        keywords: ['dashboard', 'главная', 'home']
      },
      {
        id: 'nav-pending',
        label: 'Запросы на доступ',
        icon: <ClipboardCheck size={18} />,
        action: () => navigate('/pending'),
        keywords: ['pending', 'запросы', 'requests']
      },
      {
        id: 'nav-tokens',
        label: 'Управление токенами',
        icon: <Key size={18} />,
        action: () => navigate('/tokens'),
        keywords: ['tokens', 'токены', 'keys']
      },
      {
        id: 'nav-history',
        label: 'История сканирований',
        icon: <History size={18} />,
        action: () => navigate('/history'),
        keywords: ['history', 'история', 'scans']
      },
      {
        id: 'nav-hashes',
        label: 'Подозрительные сигнатуры',
        icon: <Activity size={18} />,
        action: () => navigate('/hashes'),
        keywords: ['hashes', 'сигнатуры', 'signatures']
      },
      {
        id: 'action-logout',
        label: 'Выйти из аккаунта',
        icon: <LogOut size={18} />,
        action: () => {
          if (confirm('Вы уверены, что хотите выйти?')) {
            logout()
          }
        },
        keywords: ['logout', 'выйти', 'exit']
      }
    ]

    return items
  }, [navigate, logout])
}

function normalize(str: string) {
  return str.toLowerCase().replace(/\s+/g, ' ').trim()
}

function scoreCommand(command: CommandItem, query: string): number {
  const q = normalize(query)
  if (!q) return 1

  const label = normalize(command.label)
  const keywords = command.keywords?.map(normalize) ?? []

  if (label.startsWith(q)) return 100
  if (label.includes(q)) return 80

  for (const kw of keywords) {
    if (kw.startsWith(q)) return 70
    if (kw.includes(q)) return 60
  }

  return 0
}

export default function CommandPalette({ open, onOpenChange, withTrigger = true }: CommandPaletteProps) {
  const [query, setQuery] = useState('')
  const [activeIndex, setActiveIndex] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLUListElement>(null)
  const modalRef = useRef<HTMLDivElement>(null)
  const commands = useCommands()

  useFocusTrap(modalRef, open)

  const close = useCallback(() => onOpenChange(false), [onOpenChange])
  const toggle = useCallback(() => onOpenChange(!open), [onOpenChange, open])

  const filtered = useMemo(() => {
    if (!query.trim()) return commands
    return commands
      .map(cmd => ({ cmd, score: scoreCommand(cmd, query) }))
      .filter(({ score }) => score > 0)
      .sort((a, b) => b.score - a.score || a.cmd.label.localeCompare(b.cmd.label))
      .map(({ cmd }) => cmd)
  }, [commands, query])

  useEffect(() => {
    setActiveIndex(0)
  }, [query])

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const isCmdK = (e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k'
      if (isCmdK) {
        e.preventDefault()
        toggle()
        return
      }

      if (!open) return

      if (e.key === 'Escape') {
        close()
        return
      }

      if (e.key === 'ArrowDown') {
        e.preventDefault()
        if (filtered.length === 0) return
        setActiveIndex(prev => (prev + 1) % filtered.length)
        return
      }

      if (e.key === 'ArrowUp') {
        e.preventDefault()
        if (filtered.length === 0) return
        setActiveIndex(prev => (prev - 1 + filtered.length) % filtered.length)
        return
      }

      if (e.key === 'Enter') {
        e.preventDefault()
        const selected = filtered[activeIndex]
        if (selected) {
          selected.action()
          close()
          setQuery('')
        }
        return
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [open, filtered, activeIndex, close, toggle])

  useEffect(() => {
    if (open) {
      inputRef.current?.focus()
      setQuery('')
      setActiveIndex(0)
    }
  }, [open])

  useEffect(() => {
    const activeItem = listRef.current?.children[activeIndex]
    if (activeItem instanceof HTMLElement) {
      activeItem.scrollIntoView({ block: 'nearest' })
    }
  }, [activeIndex])

  return (
    <>
      {withTrigger && (
        <button
          className="command-palette-trigger"
          onClick={() => onOpenChange(true)}
          aria-label="Открыть командную палитру"
          title="Командная палитра (Ctrl+K / Cmd+K)"
        >
          <Search size={16} />
          <span>Поиск</span>
          <kbd className="command-kbd">⌘K</kbd>
        </button>
      )}

      <AnimatePresence>
        {open && (
          <motion.div
            className="command-palette-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={close}
          >
            <motion.div
              ref={modalRef}
              className="command-palette"
              initial={{ opacity: 0, scale: 0.96, y: -10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.96, y: -10 }}
              transition={{ duration: 0.15, ease: [0.16, 1, 0.3, 1] }}
              onClick={e => e.stopPropagation()}
            >
              <div className="command-palette-header">
                <Search size={18} className="command-palette-search-icon" />
                <input
                  ref={inputRef}
                  type="text"
                  className="command-palette-input"
                  placeholder="Найти страницу или действие..."
                  value={query}
                  onChange={e => setQuery(e.target.value)}
                  aria-label="Поиск команд"
                />
                <kbd className="command-palette-esc">ESC</kbd>
              </div>

              <ul ref={listRef} className="command-palette-list">
                {filtered.map((cmd, index) => (
                  <li
                    key={cmd.id}
                    tabIndex={0}
                    className={`command-palette-item ${index === activeIndex ? 'active' : ''}`}
                    onMouseEnter={() => setActiveIndex(index)}
                    onFocus={() => setActiveIndex(index)}
                    onClick={() => {
                      cmd.action()
                      close()
                      setQuery('')
                    }}
                    onKeyDown={e => {
                      if (e.key === 'Enter') {
                        e.preventDefault()
                        cmd.action()
                        close()
                        setQuery('')
                      }
                    }}
                  >
                    <div className="command-palette-item-icon">{cmd.icon}</div>
                    <div className="command-palette-item-body">
                      <span className="command-palette-item-label">{cmd.label}</span>
                    </div>
                    <div className="command-palette-item-action">→</div>
                  </li>
                ))}
              </ul>

              {filtered.length === 0 && (
                <div className="command-palette-empty">
                  <Command size={32} />
                  <p>Ничего не найдено</p>
                </div>
              )}

              <div className="command-palette-footer">
                  <span><kbd>↑</kbd> <kbd>↓</kbd> навигация</span>
                  <span><kbd>↵</kbd> выбрать</span>
                  <span><kbd>ESC</kbd> закрыть</span>
                </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  )
}
