import { useEffect } from 'react'
import { animate, motion, useMotionValue, useTransform } from 'framer-motion'

interface AnimatedNumberProps {
  value: number
  duration?: number
}

export default function AnimatedNumber({ value, duration = 1.5 }: AnimatedNumberProps) {
  const count = useMotionValue(0)
  const rounded = useTransform(count, (latest) => Math.round(latest).toLocaleString('ru-RU'))

  useEffect(() => {
    const controls = animate(count, value, { duration, ease: 'easeOut' })
    return () => controls.stop()
  }, [count, value, duration])

  return <motion.span>{rounded}</motion.span>
}
