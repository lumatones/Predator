import { motion } from 'framer-motion'
import { useMemo } from 'react'

interface SpeedometerGaugeProps {
  value: number
  max?: number
  size?: number
  strokeWidth?: number
}

export default function SpeedometerGauge({
  value,
  max = 10,
  size = 180,
  strokeWidth = 12,
}: SpeedometerGaugeProps) {
  const radius = (size - strokeWidth) / 2 - 8
  const centerX = size / 2
  const centerY = size / 2 + 16
  const startAngle = Math.PI
  const endAngle = 0

  const percentage = Math.min(Math.max(value / max, 0), 1)

  const arcPath = useMemo(() => {
    const x1 = centerX + radius * Math.cos(startAngle)
    const y1 = centerY + radius * Math.sin(startAngle)
    const x2 = centerX + radius * Math.cos(endAngle)
    const y2 = centerY + radius * Math.sin(endAngle)
    return `M ${x1} ${y1} A ${radius} ${radius} 0 0 1 ${x2} ${y2}`
  }, [centerX, centerY, radius])

  const color = value < 2 ? '#ff4444' : value <= 5 ? '#f59e0b' : '#22c55e'

  return (
    <div className="speedometer" style={{ width: size, height: size / 2 + 40 }}>
      <svg
        width={size}
        height={size / 2 + 40}
        viewBox={`0 0 ${size} ${size / 2 + 40}`}
        style={{ overflow: 'visible' }}
      >
        <path
          d={arcPath}
          fill="none"
          stroke="rgba(255,255,255,0.06)"
          strokeWidth={strokeWidth}
          strokeLinecap="round"
        />
        <motion.path
          d={arcPath}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          initial={{ pathLength: 0 }}
          animate={{ pathLength: percentage }}
          transition={{ duration: 1, ease: [0.16, 1, 0.3, 1] }}
        />
      </svg>
      <div className="speedometer-value" style={{ color }}>{value}</div>
      <div className="speedometer-label">Активных</div>
    </div>
  )
}
