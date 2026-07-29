import { memo, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Clock, ShieldAlert, LogOut, RefreshCw } from 'lucide-react'

interface SessionTimeoutModalProps {
  show: boolean
  remaining: number // seconds
  onExtend: () => void
  onLogout: () => void
}

function formatTime(seconds: number): string {
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  return `${m}:${s.toString().padStart(2, '0')}`
}

export default memo(function SessionTimeoutModal({
  show,
  remaining,
  onExtend,
  onLogout,
}: SessionTimeoutModalProps) {
  const extendBtnRef = useRef<HTMLButtonElement>(null)
  const isUrgent = remaining <= 60
  const isCritical = remaining <= 15

  // Auto-focus extend button when modal opens
  useEffect(() => {
    if (show) {
      setTimeout(() => extendBtnRef.current?.focus(), 100)
    }
  }, [show])

  // Get circle dashoffset for countdown ring
  const circumference = 2 * Math.PI * 54 // r=54
  const progress = remaining / 300 // 300 = 5 min total
  const dashOffset = circumference * (1 - progress)

  return (
    <AnimatePresence>
      {show && (
        <motion.div
          className="session-timeout-overlay"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.25 }}
        >
          <motion.div
            className="session-timeout-modal"
            initial={{ opacity: 0, scale: 0.92, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.92, y: 20 }}
            transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
          >
            {/* Warning icon */}
            <div className={`session-timeout-icon ${isUrgent ? 'urgent' : ''} ${isCritical ? 'critical' : ''}`}>
              <ShieldAlert size={32} />
            </div>

            {/* Title */}
            <h2 className="session-timeout-title">
              {isCritical
                ? 'Сессия будет прервана!'
                : isUrgent
                  ? 'Сессия истекает'
                  : 'Обнаружена неактивность'}
            </h2>

            <p className="session-timeout-desc">
              {isCritical
                ? 'Ваша сессия будет автоматически завершена через несколько секунд.'
                : 'Вы не проявляли активность более 25 минут. Для безопасности сессия будет завершена.'}
            </p>

            {/* Countdown ring */}
            <div className="session-timeout-countdown-wrap">
              <svg className="session-timeout-ring" width="130" height="130" viewBox="0 0 130 130">
                <circle
                  cx="65"
                  cy="65"
                  r="54"
                  fill="none"
                  stroke="rgba(255,255,255,0.06)"
                  strokeWidth="6"
                />
                <circle
                  cx="65"
                  cy="65"
                  r="54"
                  fill="none"
                  stroke={isCritical ? '#ff4444' : isUrgent ? '#eab308' : '#ff6b35'}
                  strokeWidth="6"
                  strokeLinecap="round"
                  transform="rotate(-90 65 65)"
                  strokeDasharray={circumference}
                  strokeDashoffset={dashOffset}
                  className="session-timeout-ring-progress"
                />
              </svg>
              <div className={`session-timeout-countdown ${isUrgent ? 'urgent' : ''} ${isCritical ? 'critical' : ''}`}>
                <span className="session-timeout-countdown-value">{formatTime(remaining)}</span>
                <span className="session-timeout-countdown-label">до выхода</span>
              </div>
            </div>

            {/* Progress bar (mobile-friendly) */}
            <div className="session-timeout-bar-wrap">
              <div
                className="session-timeout-bar"
                style={{
                  width: `${progress * 100}%`,
                  background: isCritical
                    ? '#ff4444'
                    : isUrgent
                      ? 'linear-gradient(90deg, #eab308, #ff6b35)'
                      : 'linear-gradient(90deg, #ff6b35, #ff4444)',
                }}
              />
            </div>

            {/* Actions */}
            <div className="session-timeout-actions">
              <button
                ref={extendBtnRef}
                className="btn btn-primary session-timeout-extend"
                onClick={onExtend}
              >
                <RefreshCw size={16} />
                Продлить сессию
              </button>
              <button
                className="btn btn-outline session-timeout-logout"
                onClick={onLogout}
              >
                <LogOut size={16} />
                Выйти сейчас
              </button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
})
