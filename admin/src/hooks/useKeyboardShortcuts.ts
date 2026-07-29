import { useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'

export interface ShortcutDef {
  key: string // e.g. '1', 'r', '/'
  ctrl?: boolean
  shift?: boolean
  label: string
  description: string
  action: () => void
  preventDefault?: boolean
}

export function useKeyboardShortcuts(
  shortcuts: ShortcutDef[],
  enabled: boolean = true
) {
  // Keep ref to avoid re-attaching listener on every render
  const shortcutsRef = useRef(shortcuts)
  shortcutsRef.current = shortcuts

  useEffect(() => {
    if (!enabled) return

    const handleKeyDown = (e: KeyboardEvent) => {
      // Don't trigger shortcuts when user is typing in an input/textarea/select
      const target = e.target as HTMLElement
      const isInput = target.tagName === 'INPUT' ||
        target.tagName === 'TEXTAREA' ||
        target.tagName === 'SELECT' ||
        target.isContentEditable
      if (isInput) return

      for (const s of shortcutsRef.current) {
        const ctrlMatch = s.ctrl ? (e.ctrlKey || e.metaKey) : true
        const shiftMatch = s.shift ? e.shiftKey : !e.shiftKey

        // For '?' — handle without Ctrl
        if (s.key === '?') {
          if (e.key === '?' && !e.ctrlKey && !e.metaKey && !e.shiftKey) {
            e.preventDefault()
            s.action()
            return
          }
          if (e.key === '/') {
            if (e.shiftKey && !e.ctrlKey && !e.metaKey) {
              e.preventDefault()
              s.action()
              return
            }
          }
          continue
        }

        const keyMatch = e.key.toLowerCase() === s.key.toLowerCase()

        if (keyMatch && ctrlMatch && shiftMatch) {
          if (s.preventDefault !== false) {
            e.preventDefault()
            e.stopPropagation()
          }
          s.action()
          return
        }
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [enabled])
}

export function useNavigationShortcuts(
  onToggleHelp: () => void,
  enabled: boolean = true
) {
  const navigate = useNavigate()

  const shortcuts: ShortcutDef[] = [
    {
      key: '1',
      ctrl: true,
      label: 'Ctrl+1',
      description: 'Главная',
      action: () => navigate('/'),
    },
    {
      key: '2',
      ctrl: true,
      label: 'Ctrl+2',
      description: 'Dashboard',
      action: () => navigate('/dashboard'),
    },
    {
      key: '3',
      ctrl: true,
      label: 'Ctrl+3',
      description: 'Запросы на доступ',
      action: () => navigate('/pending'),
    },
    {
      key: '4',
      ctrl: true,
      label: 'Ctrl+4',
      description: 'Управление токенами',
      action: () => navigate('/tokens'),
    },
    {
      key: '5',
      ctrl: true,
      label: 'Ctrl+5',
      description: 'История',
      action: () => navigate('/history'),
    },
    {
      key: '6',
      ctrl: true,
      label: 'Ctrl+6',
      description: 'Сигнатуры',
      action: () => navigate('/hashes'),
    },
    {
      key: '7',
      ctrl: true,
      label: 'Ctrl+7',
      description: 'Безопасные файлы',
      action: () => navigate('/safe-files'),
    },
    {
      key: '?',
      shift: true,
      label: 'Shift+/',
      description: 'Показать шорткаты',
      action: onToggleHelp,
    },
  ]

  useKeyboardShortcuts(shortcuts, enabled)
}
