import { motion } from 'framer-motion'
import { useMemo } from 'react'

const DEFAULT_COLORS = ['#22c55e', '#3B82F6', '#f59e0b', '#ff6b6b']

interface ConfettiProps {
  colors?: string[]
  pieceCount?: number
}

interface Piece {
  id: number
  angle: number
  distance: number
  size: number
  color: string
  rotation: number
}

export default function Confetti({ colors = DEFAULT_COLORS, pieceCount = 12 }: ConfettiProps) {
  const pieces: Piece[] = useMemo(() => {
    return Array.from({ length: pieceCount }, (_, i) => ({
      id: i,
      angle: (i / pieceCount) * Math.PI * 2,
      distance: 40 + Math.random() * 40,
      size: 4 + Math.random() * 4,
      color: colors[i % colors.length],
      rotation: Math.random() * 360,
    }))
  }, [colors, pieceCount])

  return (
    <div className="confetti-burst" aria-hidden="true">
      {pieces.map(p => (
        <motion.div
          key={p.id}
          className="confetti-piece"
          style={{ background: p.color, width: p.size, height: p.size }}
          initial={{ x: 0, y: 0, opacity: 1, scale: 1, rotate: 0 }}
          animate={{
            x: Math.cos(p.angle) * p.distance,
            y: Math.sin(p.angle) * p.distance + 20,
            opacity: 0,
            scale: 0,
            rotate: p.rotation,
          }}
          transition={{ duration: 0.7, ease: 'easeOut' }}
        />
      ))}
    </div>
  )
}
