import { useEffect, useRef, memo } from 'react'

interface MatrixRainProps {
  /** Opacity of the rain overlay (0-1), default 0.15 */
  opacity?: number
  /** Font size for the characters */
  fontSize?: number
}

function MatrixRain({ opacity = 0.15, fontSize = 13 }: MatrixRainProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    let animationId = 0
    let drops: number[] = []
    let columns = 0

    const resize = () => {
      const parent = canvas.parentElement
      if (!parent) return
      canvas.width = parent.clientWidth
      canvas.height = parent.clientHeight
      columns = Math.ceil(canvas.width / fontSize)
      drops = Array(columns).fill(1)
    }

    resize()
    window.addEventListener('resize', resize)

    const chars = '01ABCDEF0123456789アイウエオカキクケコサシスセソタチツテト'
    const greenChars = '01abcdef0123456789λφψωΔΣΩ⚡⚠✓✗▓█'

    const draw = () => {
      ctx.fillStyle = `rgba(0, 0, 0, ${0.08 / (opacity * 2)})`
      ctx.fillRect(0, 0, canvas.width, canvas.height)

      const alpha = Math.floor(opacity * 255).toString(16).padStart(2, '0')
      ctx.fillStyle = `#22c55e${alpha}`
      ctx.font = `${fontSize}px "JetBrains Mono", "Fira Code", "Cascadia Code", monospace`

      for (let i = 0; i < drops.length; i++) {
        // Leading character is brighter
        const allChars = i % 3 === 0 ? greenChars : chars
        const char = allChars[Math.floor(Math.random() * allChars.length)]
        const x = i * fontSize
        const y = drops[i] * fontSize

        // Leading char brighter
        ctx.fillStyle = `#22c55e${alpha}`
        ctx.fillText(char, x, y)

        // Trail
        if (y > fontSize && Math.random() < 0.3) {
          ctx.fillStyle = `rgba(34, 197, 94, ${opacity * 0.3})`
          const trailChar = chars[Math.floor(Math.random() * chars.length)]
          ctx.fillText(trailChar, x, y - fontSize)
        }

        if (y > canvas.height && Math.random() > 0.975) drops[i] = 0
        drops[i]++
      }
      animationId = requestAnimationFrame(draw)
    }
    draw()

    return () => {
      cancelAnimationFrame(animationId)
      window.removeEventListener('resize', resize)
    }
  }, [opacity, fontSize])

  return (
    <canvas
      ref={canvasRef}
      className="matrix-rain-canvas"
      aria-hidden="true"
      style={{ opacity }}
    />
  )
}

export default memo(MatrixRain)
