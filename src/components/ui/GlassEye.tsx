import { useEffect, useState, useCallback, useRef } from 'react'
import { motion, useSpring, useMotionValue, useReducedMotion } from 'framer-motion'

// ── Types ──

interface GlassEyeProps {
  /** Position in the viewport */
  position?: 'bottom-right' | 'bottom-left' | 'top-right' | 'center'
  /** Size of the glass card in px */
  size?: number
  /** Show scan line overlay */
  scanLine?: boolean
  /** Intensity of the creepy "look away" behavior (0-1) */
  creepiness?: number
}

// ── Constants ──

const BLINK_INTERVAL_MIN = 1800
const BLINK_INTERVAL_MAX = 4200
const BLINK_DURATION = 130
const LOOK_AWAY_INTERVAL_MIN = 5000
const LOOK_AWAY_INTERVAL_MAX = 10000
const LOOK_AWAY_DURATION_MIN = 400
const LOOK_AWAY_DURATION_MAX = 900

const POSITION_CLASSES: Record<string, string> = {
  'bottom-right': 'glass-eye--br',
  'bottom-left': 'glass-eye--bl',
  'top-right': 'glass-eye--tr',
  'center': 'glass-eye--center',
}

// ── Component ──

export default function GlassEye({
  position = 'bottom-right',
  size = 100,
  scanLine = true,
  creepiness = 0.6,
}: GlassEyeProps) {
  const prefersReduced = useReducedMotion()
  const isReduced = prefersReduced === true

  // Spring-animated cursor position (laggy = creepy)
  const springX = useMotionValue(0)
  const springY = useMotionValue(0)
  const pupilX = useSpring(springX, { stiffness: 70, damping: isReduced ? 30 : 14 })
  const pupilY = useSpring(springY, { stiffness: 70, damping: isReduced ? 30 : 14 })

  // Blink state
  const [blinking, setBlinking] = useState(false)

  // Look-away — use ref to avoid useEffect re-registration churn
  const lookingAwayRef = useRef(false)
  const lookAwayOffset = useRef({ x: 0, y: 0 })

  // Track if component is mounted
  const mounted = useRef(true)

  // ── Cursor tracking ──

  useEffect(() => {
    if (isReduced) return

    const handleMouseMove = (e: MouseEvent) => {
      if (lookingAwayRef.current) return

      const cx = (e.clientX / window.innerWidth - 0.5) * 2
      const cy = (e.clientY / window.innerHeight - 0.5) * 2
      const range = size * 0.14
      springX.set(cx * range)
      springY.set(cy * range)
    }

    window.addEventListener('mousemove', handleMouseMove, { passive: true })
    return () => window.removeEventListener('mousemove', handleMouseMove)
  }, [springX, springY, size, isReduced]) // lookingAway removed — uses ref instead

  // ── Blinking ──

  const scheduleBlink = useCallback(() => {
    if (!mounted.current || isReduced) return
    const delay = BLINK_INTERVAL_MIN + Math.random() * (BLINK_INTERVAL_MAX - BLINK_INTERVAL_MIN)
    const timer = setTimeout(() => {
      if (!mounted.current) return
      setBlinking(true)
      setTimeout(() => {
        if (mounted.current) setBlinking(false)
      }, BLINK_DURATION)
      scheduleBlink()
    }, delay)
    return timer
  }, [isReduced])

  useEffect(() => {
    mounted.current = true
    if (isReduced) return
    const timer = scheduleBlink()
    return () => {
      mounted.current = false
      if (timer) clearTimeout(timer)
    }
  }, [scheduleBlink, isReduced])

  // ── Look-away (creepy drift) ──

  const scheduleLookAway = useCallback(() => {
    if (!mounted.current || isReduced || creepiness < 0.2) return
    const delay = LOOK_AWAY_INTERVAL_MIN + Math.random() * (LOOK_AWAY_INTERVAL_MAX - LOOK_AWAY_INTERVAL_MIN)
    const timer = setTimeout(() => {
      if (!mounted.current) return

      const angle = Math.random() * Math.PI * 2
      const distance = size * 0.06 + Math.random() * size * 0.08 * creepiness
      lookAwayOffset.current = {
        x: Math.cos(angle) * distance,
        y: Math.sin(angle) * distance,
      }

      lookingAwayRef.current = true
      springX.set(lookAwayOffset.current.x)
      springY.set(lookAwayOffset.current.y)

      const duration = LOOK_AWAY_DURATION_MIN + Math.random() * (LOOK_AWAY_DURATION_MAX - LOOK_AWAY_DURATION_MIN)
      setTimeout(() => {
        if (mounted.current) {
          lookingAwayRef.current = false
        }
      }, duration)

      scheduleLookAway()
    }, delay)
    return timer
  }, [springX, springY, size, isReduced, creepiness])

  useEffect(() => {
    if (isReduced) return
    const timer = scheduleLookAway()
    return () => { if (timer) clearTimeout(timer) }
  }, [scheduleLookAway, isReduced])

  // ── Eye dimensions ──

  const eyeSize = size * 0.5
  const irisSize = eyeSize * 0.55
  const pupilDiameter = irisSize * 0.38

  return (
    <motion.div
      className={`glass-eye ${POSITION_CLASSES[position] || POSITION_CLASSES['bottom-right']}`}
      style={{
        width: size,
        height: size,
        ...(position === 'center' ? { marginLeft: -size / 2, marginTop: -size / 2 } : {}),
      }}
      initial={isReduced ? false : { opacity: 0, scale: 0.8, filter: 'blur(8px)' }}
      animate={{ opacity: 1, scale: 1, filter: 'blur(0px)' }}
      transition={isReduced ? { duration: 0 } : { duration: 0.8, ease: [0.16, 1, 0.3, 1], delay: 0.4 }}
      whileHover={isReduced ? undefined : { scale: 1.05 }}
    >
      {/* Glass card background */}
      <div className="glass-eye-card">
        {/* Scan line overlay */}
        {scanLine && <div className="glass-eye-scanline" />}

        {/* Eye */}
        <div className="glass-eye-eye" style={{ width: eyeSize, height: eyeSize }}>
          {/* Iris */}
          <motion.div
            className="glass-eye-iris"
            style={{ width: irisSize, height: irisSize, x: pupilX, y: pupilY }}
          >
            {/* Pupil */}
            <motion.div
              className="glass-eye-pupil"
              style={{ width: pupilDiameter, height: pupilDiameter }}
              animate={isReduced ? {} : {
                scaleY: blinking ? 0.08 : 1,
                scaleX: blinking ? 1.15 : 1,
              }}
              transition={{
                scaleY: { duration: 0.06, ease: 'easeIn' },
                scaleX: { duration: 0.06, ease: 'easeIn', delay: 0.03 },
              }}
            />
            {/* Iris highlight ring */}
            <div className="glass-eye-iris-ring" />
          </motion.div>

          {/* Eye shine/reflection */}
          <div className="glass-eye-shine" />
        </div>
      </div>

      {/* Ambient red glow behind the card */}
      <div className="glass-eye-glow" />
    </motion.div>
  )
}
