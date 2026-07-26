import * as React from 'react'
import * as ToastPrimitive from '@radix-ui/react-toast'

export type ToastVariant = 'success' | 'error' | 'warning' | 'info'

export interface ToastItemData {
  id: string
  variant: ToastVariant
  title?: string
  description?: string
}

const variantIcon: Record<ToastVariant, string> = {
  success: '✓',
  error: '✕',
  warning: '!',
  info: 'i',
}

const variantClass: Record<ToastVariant, string> = {
  success: 'toast-success',
  error: 'toast-error',
  warning: 'toast-warning',
  info: 'toast-info',
}

interface ToastItemProps extends ToastItemData {
  onRemove: (id: string) => void
}

export const ToastItem: React.FC<ToastItemProps> = ({ id, variant, title, description, onRemove }) => {
  React.useEffect(() => {
    const timer = setTimeout(() => onRemove(id), 5000)
    return () => clearTimeout(timer)
  }, [id, onRemove])

  return (
    <ToastPrimitive.Root
      className={`toast-root ${variantClass[variant]}`}
      open
      onOpenChange={open => !open && onRemove(id)}
      duration={Infinity}
    >
      <div className="toast-indicator"><span>{variantIcon[variant]}</span></div>
      <div className="toast-body">
        {title && <ToastPrimitive.Title className="toast-title">{title}</ToastPrimitive.Title>}
        {description && <ToastPrimitive.Description className="toast-description">{description}</ToastPrimitive.Description>}
      </div>
      <ToastPrimitive.Close asChild>
        <button className="toast-close" aria-label="Close">×</button>
      </ToastPrimitive.Close>
    </ToastPrimitive.Root>
  )
}
