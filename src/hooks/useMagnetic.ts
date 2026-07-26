import { useEffect, useRef } from 'react'
import { useReducedMotion } from 'framer-motion'

export function useMagnetic<T extends HTMLElement>(strength = 0.3) {
  const ref = useRef<T>(null)
  const reducedMotion = useReducedMotion()

  useEffect(() => {
    const el = ref.current
    if (!el || reducedMotion !== false) return

    const handleMove = (e: MouseEvent) => {
      const rect = el.getBoundingClientRect()
      const x = e.clientX - rect.left - rect.width / 2
      const y = e.clientY - rect.top - rect.height / 2
      el.style.transform = `translate(${x * strength}px, ${y * strength}px)`
      el.style.transition = 'none'
    }

    const handleLeave = () => {
      el.style.transition = 'transform 0.3s ease-out'
      el.style.transform = 'translate(0, 0)'
    }

    el.addEventListener('mousemove', handleMove)
    el.addEventListener('mouseleave', handleLeave)
    return () => {
      el.removeEventListener('mousemove', handleMove)
      el.removeEventListener('mouseleave', handleLeave)
      if (el) {
        el.style.transform = ''
        el.style.transition = ''
      }
    }
  }, [strength, reducedMotion])

  return ref
}
