import { useContext } from 'react'
import { ToastContext } from '../components/ui/ToastProvider'
import type { ToastVariant } from '../components/ui/Toast'

export function useToast() {
  const ctx = useContext(ToastContext)
  if (!ctx) {
    throw new Error('useToast must be used within a ToastProvider')
  }

  const makeToast = (variant: ToastVariant) => (description: string, title?: string) => {
    ctx.addToast({ variant, title, description })
  }

  return {
    toast: {
      success: makeToast('success'),
      error: makeToast('error'),
      warning: makeToast('warning'),
      info: makeToast('info'),
    },
  }
}
