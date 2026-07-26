import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import type { ThemeColors } from '../../types'

interface ThemeBurnTransitionProps {
  isActive: boolean
  oldColors: ThemeColors
  newColors: ThemeColors
  onComplete?: () => void
}

/**
 * Эффект «сгорания бумаги» — диагональный прожог от левого верхнего
 * угла к правому нижнему. Старая тема «сгорает», открывая новую.
 */
export default function ThemeBurnTransition({
  isActive,
  oldColors,
  newColors,
  onComplete,
}: ThemeBurnTransitionProps) {
  const [phase, setPhase] = useState<'idle' | 'burning' | 'done'>('idle')

  useEffect(() => {
    if (isActive && phase === 'idle') {
      setPhase('burning')
    }
  }, [isActive, phase])

  const handleAnimationComplete = useCallback(() => {
    setPhase('done')
    onComplete?.()
  }, [onComplete])

  if (!isActive && phase === 'done') return null

  return (
    <AnimatePresence>
      {(isActive || phase === 'burning') && (
        <motion.div
          className="theme-burn-overlay"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.25 }}
        >
          {/* Старый фон (сгорает) */}
          <motion.div
            className="theme-burn-old"
            style={{
              position: 'absolute',
              inset: 0,
              background: `radial-gradient(ellipse at center, ${oldColors.bg} 0%, #020202 100%)`,
            }}
            initial={{ clipPath: 'polygon(0 0, 0 0, 0 0, 0 0)' }}
            animate={{
              clipPath: [
                'polygon(0 0, 0 0, 0 0, 0 0)',
                'polygon(0 0, 35% 0, 5% 35%, 0 25%)',
                'polygon(0 0, 100% 0, 65% 25%, 15% 45%, 0 35%)',
                'polygon(0 0, 100% 0, 100% 45%, 45% 100%, 0 75%)',
                'polygon(0 0, 100% 0, 100% 100%, 0 100%)',
              ],
            }}
            transition={{
              duration: 0.8,
              ease: [0.22, 1, 0.36, 1],
              times: [0, 0.2, 0.45, 0.7, 1],
            }}
            onAnimationComplete={handleAnimationComplete}
          >
            {/* Огненная кромка по диагонали */}
            <motion.div
              className="theme-burn-flame"
              style={{
                position: 'absolute',
                inset: 0,
                background: `linear-gradient(135deg, ${oldColors.accent}50 0%, ${oldColors.light}25 30%, transparent 55%)`,
              }}
              initial={{ opacity: 0 }}
              animate={{ opacity: [0, 0.9, 0.7, 0.2, 0] }}
              transition={{ duration: 0.8, times: [0, 0.1, 0.35, 0.65, 1] }}
            />
            {/* Искры */}
            <motion.div
              className="theme-burn-sparks"
              style={{
                position: 'absolute',
                inset: 0,
                background: `
                  radial-gradient(circle at 25% 25%, ${oldColors.accent}70 0%, transparent 2.5%),
                  radial-gradient(circle at 55% 15%, ${oldColors.light}60 0%, transparent 2%),
                  radial-gradient(circle at 40% 55%, ${oldColors.accent}50 0%, transparent 3%),
                  radial-gradient(circle at 70% 65%, ${oldColors.light}40 0%, transparent 2%),
                  radial-gradient(circle at 85% 85%, ${oldColors.accent}30 0%, transparent 1.5%)
                `,
              }}
              initial={{ opacity: 0 }}
              animate={{ opacity: [0, 0.7, 0.5, 0] }}
              transition={{ duration: 0.8, times: [0, 0.15, 0.45, 1] }}
            />
          </motion.div>

          {/* Новый фон (проявляется) */}
          <motion.div
            className="theme-burn-new"
            style={{
              position: 'absolute',
              inset: 0,
              background: `radial-gradient(ellipse at center, ${newColors.bg} 0%, #020202 100%)`,
            }}
            initial={{ opacity: 0 }}
            animate={{ opacity: [0, 0, 0.3, 1] }}
            transition={{ duration: 0.8, times: [0, 0.3, 0.55, 1] }}
          />

          {/* Вспышка в момент перехода */}
          <motion.div
            className="theme-burn-flash"
            style={{
              position: 'absolute',
              inset: 0,
              background: newColors.accent,
            }}
            initial={{ opacity: 0 }}
            animate={{ opacity: [0, 0.12, 0] }}
            transition={{ duration: 0.5, delay: 0.3 }}
          />
        </motion.div>
      )}
    </AnimatePresence>
  )
}
