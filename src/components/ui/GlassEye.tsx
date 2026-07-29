import { useEffect, useState, useCallback, useRef } from 'react'
import { motion, useSpring, useMotionValue, useReducedMotion } from 'framer-motion'

// ── Types ──

interface GlassEyeProps {
  /** Position in the viewport (ignored when inline) */
  position?: 'bottom-right' | 'bottom-left' | 'top-right' | 'center'
  /** Size of the glass card in px */
  size?: number
  /** Show scan line overlay */
  scanLine?: boolean
  /** Intensity of the creepy "look away" behavior (0-1) */
  creepiness?: number
  /** Render inline (position: relative) — for use inside flex/grid containers */
  inline?: boolean
  /** Frenzied scary mode — jittery, dilated, unhinged */
  frenzied?: boolean
}

// ── Constants ──

const BLINK_INTERVAL_MIN = 1800
const BLINK_INTERVAL_MAX = 4200
const BLINK_DURATION = 120
const DOUBLE_BLINK_CHANCE = 0.25       // 25% chance of double-blink
const DOUBLE_BLINK_GAP = 140           // ms between the two blinks

const LOOK_AWAY_INTERVAL_MIN = 4500
const LOOK_AWAY_INTERVAL_MAX = 9000
const LOOK_AWAY_DURATION_MIN = 350
const LOOK_AWAY_DURATION_MAX = 850

// In frenzied mode: faster, bigger drifts
const FRENZIED_DRIFT_INTERVAL_MIN = 180
const FRENZIED_DRIFT_INTERVAL_MAX = 600

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
  inline = false,
  frenzied = false,
}: GlassEyeProps) {
  const prefersReduced = useReducedMotion()
  const isReduced = prefersReduced === true

  // Spring-animated cursor position (laggy = creepy)
  const springX = useMotionValue(0)
  const springY = useMotionValue(0)

  // In frenzied mode use very loose springs for twitchy feel
  const stiffness = frenzied ? 40 : 70
  const damping = frenzied ? 6 : (isReduced ? 30 : 14)
  const pupilX = useSpring(springX, { stiffness, damping })
  const pupilY = useSpring(springY, { stiffness, damping })

  // Blink state
  const [blinking, setBlinking] = useState(false)

  // Iris dilation state (frenzied = fully dilated)
  const [pupilScale, setPupilScale] = useState(1)

  // Look-away — use ref to avoid useEffect re-registration churn
  const lookingAwayRef = useRef(false)
  const lookAwayOffset = useRef({ x: 0, y: 0 })

  // Track if component is mounted
  const mounted = useRef(true)

  // ── Cursor tracking ──

  useEffect(() => {
    if (isReduced) return

    const handleMouseMove = (e: MouseEvent) => {
      if (lookingAwayRef.current && !frenzied) return

      const cx = (e.clientX / window.innerWidth - 0.5) * 2
      const cy = (e.clientY / window.innerHeight - 0.5) * 2
      const range = size * (frenzied ? 0.2 : 0.14)
      springX.set(cx * range)
      springY.set(cy * range)
    }

    window.addEventListener('mousemove', handleMouseMove, { passive: true })
    return () => window.removeEventListener('mousemove', handleMouseMove)
  }, [springX, springY, size, isReduced, frenzied])

  // ── Blinking (with optional double-blink) ──

  const doSingleBlink = useCallback(() => {
    if (!mounted.current) return
    setBlinking(true)
    setTimeout(() => {
      if (mounted.current) setBlinking(false)
    }, BLINK_DURATION)
  }, [])

  const scheduleBlink = useCallback(() => {
    if (!mounted.current || isReduced) return
    // In frenzied mode blink much faster
    const minInterval = frenzied ? 300 : BLINK_INTERVAL_MIN
    const maxInterval = frenzied ? 900 : BLINK_INTERVAL_MAX
    const delay = minInterval + Math.random() * (maxInterval - minInterval)

    const timer = setTimeout(() => {
      if (!mounted.current) return
      doSingleBlink()

      // Double-blink: occasionally blink a second time shortly after
      const willDoubleOrTriple = Math.random() < (frenzied ? 0.6 : DOUBLE_BLINK_CHANCE)
      if (willDoubleOrTriple) {
        setTimeout(() => {
          if (mounted.current) doSingleBlink()
          // Triple blink in frenzied mode
          if (frenzied && Math.random() < 0.3) {
            setTimeout(() => { if (mounted.current) doSingleBlink() }, DOUBLE_BLINK_GAP)
          }
        }, DOUBLE_BLINK_GAP)
      }

      scheduleBlink()
    }, delay)
    return timer
  }, [isReduced, frenzied, doSingleBlink])

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
      const distance = size * 0.06 + Math.random() * size * 0.1 * creepiness
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

  // ── Frenzied drift — rapid random twitching ──

  useEffect(() => {
    if (!frenzied || isReduced) return

    let timerId: ReturnType<typeof setTimeout>

    const twitch = () => {
      if (!mounted.current) return
      const angle = Math.random() * Math.PI * 2
      const distance = size * 0.05 + Math.random() * size * 0.18
      springX.set(Math.cos(angle) * distance)
      springY.set(Math.sin(angle) * distance)

      const nextDelay = FRENZIED_DRIFT_INTERVAL_MIN + Math.random() * (FRENZIED_DRIFT_INTERVAL_MAX - FRENZIED_DRIFT_INTERVAL_MIN)
      timerId = setTimeout(twitch, nextDelay)
    }

    timerId = setTimeout(twitch, 100)
    return () => clearTimeout(timerId)
  }, [frenzied, isReduced, springX, springY, size])

  // ── Frenzied pupil dilation pulse ──

  useEffect(() => {
    if (!frenzied || isReduced) return

    let timer: ReturnType<typeof setTimeout>
    const pulse = () => {
      if (!mounted.current) return
      const scale = 1.2 + Math.random() * 0.6  // 1.2x – 1.8x
      setPupilScale(scale)
      timer = setTimeout(pulse, 200 + Math.random() * 500)
    }
    pulse()
    return () => clearTimeout(timer)
  }, [frenzied, isReduced])

  // Reset pupil scale when not frenzied
  useEffect(() => {
    if (!frenzied) setPupilScale(1)
  }, [frenzied])

  // ── Eye dimensions ──

  const eyeSize = size * 0.5
  const irisSize = eyeSize * 0.55
  const pupilDiameter = irisSize * 0.38

  return (
    <motion.div
      className={[
        'glass-eye',
        inline ? 'glass-eye--inline' : '',
        frenzied ? 'glass-eye--frenzied' : '',
        POSITION_CLASSES[position] || POSITION_CLASSES['bottom-right'],
      ].filter(Boolean).join(' ')}
      style={{
        width: size,
        height: size,
        ...(!inline && position === 'center' ? { marginLeft: -size / 2, marginTop: -size / 2 } : {}),
      }}
      initial={isReduced ? false : { opacity: 0, scale: 0.8, filter: 'blur(8px)' }}
      animate={{
        opacity: 1,
        scale: frenzied ? [1, 1.04, 0.97, 1.02, 1] : 1,
        filter: 'blur(0px)',
      }}
      transition={isReduced ? { duration: 0 } : {
        duration: frenzied ? 0.3 : 0.8,
        ease: [0.16, 1, 0.3, 1],
        delay: frenzied ? 0 : 0.4,
        scale: frenzied ? { duration: 0.3, repeat: Infinity, repeatType: 'mirror', ease: 'easeInOut' } : undefined,
      }}
      whileHover={isReduced || frenzied ? undefined : { scale: 1.05 }}
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
            animate={frenzied ? { rotate: [0, 2, -3, 1, -1, 0] } : {}}
            transition={frenzied ? { duration: 0.4, repeat: Infinity, ease: 'linear' } : {}}
          >
            {/* Pupil */}
            <motion.div
              className="glass-eye-pupil"
              style={{ width: pupilDiameter, height: pupilDiameter }}
              animate={isReduced ? {} : {
                scaleY: blinking ? 0.06 : pupilScale,
                scaleX: blinking ? 1.2 : (frenzied ? pupilScale * 0.9 : 1),
              }}
              transition={{
                scaleY: { duration: blinking ? 0.055 : 0.4, ease: blinking ? 'easeIn' : [0.16, 1, 0.3, 1] },
                scaleX: { duration: blinking ? 0.055 : 0.4, ease: blinking ? 'easeIn' : [0.16, 1, 0.3, 1], delay: blinking ? 0.025 : 0 },
              }}
            />
            {/* Iris highlight ring */}
            <div className="glass-eye-iris-ring" />
            {/* Inner iris glow — subtle limbal ring */}
            <div className="glass-eye-iris-limbal" />
          </motion.div>

          {/* Eye shine/reflection — primary */}
          <div className="glass-eye-shine" />
          {/* Secondary reflection — micro sparkle */}
          <div className="glass-eye-shine-2" />
        </div>
      </div>

      {/* Ambient red glow behind the card */}
      <div className={`glass-eye-glow${frenzied ? ' glass-eye-glow--frenzied' : ''}`} />
    </motion.div>
  )
}
