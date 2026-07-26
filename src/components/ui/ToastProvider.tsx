import * as React from 'react'
import * as ToastPrimitive from '@radix-ui/react-toast'
import { AnimatePresence, motion } from 'framer-motion'
import { ToastItem, ToastItemData } from './Toast'

interface ToastContextValue {
  addToast: (toast: Omit<ToastItemData, 'id'>) => void
}

export const ToastContext = React.createContext<ToastContextValue | null>(null)

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [toasts, setToasts] = React.useState<ToastItemData[]>([])
  const idRef = React.useRef(0)

  const addToast = React.useCallback((toast: Omit<ToastItemData, 'id'>) => {
    idRef.current += 1
    const id = `toast-${idRef.current}`
    setToasts(prev => {
      const next = [...prev, { id, ...toast }]
      return next.length > 5 ? next.slice(next.length - 5) : next
    })
  }, [])

  const removeToast = React.useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  return (
    <ToastContext.Provider value={{ addToast }}>
      <ToastPrimitive.Provider swipeDirection="right">
        {children}
        <ToastPrimitive.Viewport className="toast-viewport" label="Notifications" asChild>
          <motion.div layout className="toast-stack">
            <AnimatePresence initial={false}>
              {toasts.map(t => (
                <motion.div
                  key={t.id}
                  layout
                  initial={{ opacity: 0, x: 60, scale: 0.95 }}
                  animate={{ opacity: 1, x: 0, scale: 1 }}
                  exit={{ opacity: 0, x: 40, scale: 0.95 }}
                  transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
                  className="toast-item"
                >
                  <ToastItem {...t} onRemove={removeToast} />
                </motion.div>
              ))}
            </AnimatePresence>
          </motion.div>
        </ToastPrimitive.Viewport>
      </ToastPrimitive.Provider>
    </ToastContext.Provider>
  )
}
