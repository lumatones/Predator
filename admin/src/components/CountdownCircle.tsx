import { useState, useEffect, memo } from 'react'

interface CountdownCircleProps {
  expiresAt: string
  createdAt: string
  size?: number
  stroke?: number
}

const STATUS_COLORS = {
  green: '#22c55e',
  yellow: '#eab308',
  red: '#ff4444',
  grey: '#64748b',
}

type Status = keyof typeof STATUS_COLORS

function CountdownCircle({ expiresAt, createdAt, size = 64, stroke = 6 }: CountdownCircleProps) {
  const radius = (size - stroke) / 2
  const center = size / 2
  const circumference = 2 * Math.PI * radius

  const [status, setStatus] = useState<Status>('green')
  const [progress, setProgress] = useState(1)
  const [label, setLabel] = useState('')

  useEffect(() => {
    const max = Math.max(0, new Date(expiresAt).getTime() - new Date(createdAt).getTime())

    function update() {
      const remaining = new Date(expiresAt).getTime() - Date.now()
      const fraction = max > 0 ? Math.max(0, Math.min(1, remaining / max)) : 0
      setProgress(fraction)

      if (remaining <= 0) {
        setStatus('grey')
        setLabel('Истёк')
      } else if (remaining < 5 * 60 * 1000) {
        setStatus('red')
        const m = Math.floor(remaining / 60000)
        const s = Math.floor((remaining % 60000) / 1000)
        setLabel(`${m}м ${s}с`)
      } else if (remaining < 60 * 60 * 1000) {
        setStatus('yellow')
        const m = Math.floor(remaining / 60000)
        setLabel(`${m} мин`)
      } else {
        setStatus('green')
        const h = Math.floor(remaining / 3600000)
        const m = Math.floor((remaining % 3600000) / 60000)
        setLabel(`${h}ч ${m}м`)
      }
    }

    update()
    const timer = setInterval(update, 1000)
    return () => clearInterval(timer)
  }, [expiresAt, createdAt])

  const dashOffset = circumference * (1 - progress)
  const color = STATUS_COLORS[status]

  return (
    <div className={`countdown-circle ${status}`} role="img" aria-label={`Осталось времени: ${label}`}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="countdown-svg">
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="none"
          stroke="rgba(255,255,255,0.08)"
          strokeWidth={stroke}
        />
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          style={{ transform: 'rotate(-90deg)', transformOrigin: '50% 50%', transition: 'stroke-dashoffset 0.5s ease, stroke 0.3s ease' }}
        />
      </svg>
      <span className="countdown-label">{label}</span>
      {status === 'red' && <span className="countdown-pulse" />}
    </div>
  )
}

export default memo(CountdownCircle)
