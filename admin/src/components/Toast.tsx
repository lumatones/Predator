import { useEffect, useCallback, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { springEase } from '../constants'

export type ToastType = 'success' | 'warning' | 'info' | 'error'

export interface ToastItem {
  id: number
  type: ToastType
  message: string
}

const config: Record<ToastType, { border: string; glow: string; iconColor: string }> = {
  success: { border: 'rgba(34,197,94,0.35)', glow: 'rgba(34,197,94,0.2)', iconColor: '#22c55e' },
  warning: { border: 'rgba(234,179,8,0.35)', glow: 'rgba(234,179,8,0.2)', iconColor: '#eab308' },
  info:    { border: 'rgba(59,130,246,0.35)', glow: 'rgba(59,130,246,0.2)', iconColor: '#3B82F6' },
  error:   { border: 'rgba(255,68,68,0.35)',  glow: 'rgba(255,68,68,0.2)',  iconColor: '#ff6b6b' },
}

export function useToasts() {
  const [toasts, setToasts] = useState<ToastItem[]>([])

  const addToast = useCallback((type: ToastType, message: string) => {
    const id = Date.now() + Math.random()
    setToasts(prev => [...prev, { id, type, message }])
  }, [])

  const removeToast = useCallback((id: number) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  return { toasts, addToast, removeToast }
}

function ToastBubble({ toast, onRemove }: { toast: ToastItem; onRemove: (id: number) => void }) {
  useEffect(() => {
    const timer = setTimeout(() => onRemove(toast.id), 5000)
    return () => clearTimeout(timer)
  }, [toast.id, onRemove])

  return (
    <motion.div
      className="toast glass-toast"
      layout
      role="button"
      tabIndex={0}
      style={{ borderLeft: `3px solid ${config[toast.type].border}` }}
      initial={{ x: 80, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      exit={{ x: 80, opacity: 0 }}
      transition={{ duration: 0.25, ease: springEase }}
      onClick={() => onRemove(toast.id)}
      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') onRemove(toast.id) }}
      aria-label="Закрыть уведомление"
    >
      <span className="toast-glow" style={{ background: config[toast.type].glow }} />
      <span className="toast-message" style={{ color: config[toast.type].iconColor }}>{toast.message}</span>
    </motion.div>
  )
}

export function ToastContainer({ toasts, onRemove }: {
  toasts: ToastItem[]
  onRemove: (id: number) => void
}) {
  return (
    <div className="toast-container">
      <AnimatePresence>
        {toasts.map(t => (
          <ToastBubble key={t.id} toast={t} onRemove={onRemove} />
        ))}
      </AnimatePresence>
    </div>
  )
}
