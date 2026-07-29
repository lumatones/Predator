import { useState, useEffect, useRef, useCallback } from 'react'

const SESSION_DURATION = 30 * 60 * 1000 // 30 минут бездействия
const WARNING_BEFORE = 5 * 60 * 1000 // предупреждение за 5 мин до окончания
const WARNING_AT = SESSION_DURATION - WARNING_BEFORE // 25 мин

interface SessionState {
  showWarning: boolean
  remaining: number // seconds until auto-logout (from warning)
}

export function useSessionTimeout(
  isAuthenticated: boolean,
  onTimeout: () => void
): SessionState {
  const [showWarning, setShowWarning] = useState(false)
  const [remaining, setRemaining] = useState(300)
  const lastActivity = useRef<ReturnType<typeof Date.now>>(Date.now())
  const checkInterval = useRef<ReturnType<typeof setInterval> | undefined>(undefined)
  const warningInterval = useRef<ReturnType<typeof setInterval> | undefined>(undefined)
  const warningStart = useRef<ReturnType<typeof Date.now>>(0)
  const warningShownRef = useRef(false)
  const onTimeoutRef = useRef(onTimeout)

  // Keep callback ref fresh without triggering effect re-runs
  onTimeoutRef.current = onTimeout

  // Reset timer on user activity
  const handleActivity = useCallback(() => {
    lastActivity.current = Date.now()
    if (warningShownRef.current) {
      warningShownRef.current = false
      setShowWarning(false)
      setRemaining(300)
      if (warningInterval.current) {
        clearInterval(warningInterval.current)
        warningInterval.current = undefined
      }
    }
  }, [])

  // Attach activity listeners
  useEffect(() => {
    if (!isAuthenticated) return

    const events = ['mousedown', 'keydown', 'touchstart', 'scroll', 'mousemove', 'wheel']
    events.forEach(ev => window.addEventListener(ev, handleActivity, { passive: true }))

    return () => {
      events.forEach(ev => window.removeEventListener(ev, handleActivity))
    }
  }, [isAuthenticated, handleActivity])

  // Check inactivity every second
  useEffect(() => {
    if (!isAuthenticated) return

    checkInterval.current = setInterval(() => {
      const elapsed = Date.now() - lastActivity.current

      if (elapsed >= SESSION_DURATION) {
        // Force logout
        warningShownRef.current = false
        setShowWarning(false)
        if (warningInterval.current) {
          clearInterval(warningInterval.current)
          warningInterval.current = undefined
        }
        onTimeoutRef.current()
        return
      }

      if (elapsed >= WARNING_AT && !warningShownRef.current) {
        warningShownRef.current = true
        warningStart.current = Date.now()
        setShowWarning(true)
        setRemaining(WARNING_BEFORE / 1000)

        // Start countdown every 200ms for smooth UI
        if (warningInterval.current) {
          clearInterval(warningInterval.current)
        }
        warningInterval.current = setInterval(() => {
          const elapsedSinceWarning = Date.now() - warningStart.current
          const secs = Math.max(0, Math.ceil((WARNING_BEFORE - elapsedSinceWarning) / 1000))
          setRemaining(secs)

          if (secs <= 0) {
            if (warningInterval.current) {
              clearInterval(warningInterval.current)
              warningInterval.current = undefined
            }
            warningShownRef.current = false
            setShowWarning(false)
            onTimeoutRef.current()
          }
        }, 200)
      }
    }, 1000)

    return () => {
      if (checkInterval.current) {
        clearInterval(checkInterval.current)
        checkInterval.current = undefined
      }
      if (warningInterval.current) {
        clearInterval(warningInterval.current)
        warningInterval.current = undefined
      }
    }
  }, [isAuthenticated])

  return { showWarning, remaining }
}
