import { memo, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { X, Keyboard, Command } from 'lucide-react'

interface ShortcutItem {
  key: string
  description: string
}

interface KeyboardShortcutsHelpProps {
  open: boolean
  onClose: () => void
}

const NAV_SHORTCUTS: ShortcutItem[] = [
  { key: 'Ctrl+1', description: 'Главная' },
  { key: 'Ctrl+2', description: 'Dashboard' },
  { key: 'Ctrl+3', description: 'Запросы на доступ' },
  { key: 'Ctrl+4', description: 'Управление токенами' },
  { key: 'Ctrl+5', description: 'История' },
  { key: 'Ctrl+6', description: 'Сигнатуры' },
  { key: 'Ctrl+7', description: 'Безопасные файлы' },
]

const APP_SHORTCUTS: ShortcutItem[] = [
  { key: 'Ctrl+K', description: 'Командная палитра' },
  { key: 'Shift+/', description: 'Показать шорткаты' },
  { key: '↑ ↓', description: 'Навигация в палитре' },
  { key: 'Enter', description: 'Подтвердить' },
  { key: 'Esc', description: 'Закрыть' },
]

function Kbd({ children }: { children: string }) {
  return <kbd className="shortcut-kbd">{children}</kbd>
}

export default memo(function KeyboardShortcutsHelp({ open, onClose }: KeyboardShortcutsHelpProps) {
  const overlayRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && open) onClose()
    }
    window.addEventListener('keydown', handleKey)
    return () => window.removeEventListener('keydown', handleKey)
  }, [open, onClose])

  useEffect(() => {
    if (open) {
      document.body.style.overflow = 'hidden'
    } else {
      document.body.style.overflow = ''
    }
    return () => { document.body.style.overflow = '' }
  }, [open])

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          ref={overlayRef}
          className="shortcuts-overlay"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.2 }}
          onClick={(e) => { if (e.target === overlayRef.current) onClose() }}
        >
          <motion.div
            className="shortcuts-modal"
            initial={{ opacity: 0, scale: 0.95, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 20 }}
            transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
          >
            {/* Header */}
            <div className="shortcuts-header">
              <div className="shortcuts-header-left">
                <div className="shortcuts-header-icon">
                  <Keyboard size={22} />
                </div>
                <div>
                  <h2 className="shortcuts-title">Горячие клавиши</h2>
                  <span className="shortcuts-subtitle">Управление админ-панелью с клавиатуры</span>
                </div>
              </div>
              <button className="shortcuts-close-btn" onClick={onClose} aria-label="Закрыть">
                <X size={20} />
              </button>
            </div>

            {/* Body */}
            <div className="shortcuts-body">
              {/* Navigation section */}
              <div className="shortcuts-section">
                <div className="shortcuts-section-header">
                  <Command size={15} />
                  <span>Навигация</span>
                </div>
                <div className="shortcuts-grid">
                  {NAV_SHORTCUTS.map(item => (
                    <div key={item.key} className="shortcuts-row">
                      <Kbd>{item.key}</Kbd>
                      <span className="shortcuts-desc">{item.description}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="shortcuts-divider" />

              {/* App section */}
              <div className="shortcuts-section">
                <div className="shortcuts-section-header">
                  <Keyboard size={15} />
                  <span>Приложение</span>
                </div>
                <div className="shortcuts-grid">
                  {APP_SHORTCUTS.map(item => (
                    <div key={item.key} className="shortcuts-row">
                      <Kbd>{item.key}</Kbd>
                      <span className="shortcuts-desc">{item.description}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Footer */}
            <div className="shortcuts-footer">
              <p>Нажмите <Kbd>Shift+/</Kbd> в любой момент, чтобы открыть эту панель</p>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
})
