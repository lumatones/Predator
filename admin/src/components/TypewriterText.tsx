import { useState, useEffect } from 'react'

interface TypewriterTextProps {
  text: string
  speed?: number
  className?: string
}

export default function TypewriterText({ text, speed = 40, className }: TypewriterTextProps) {
  const [displayed, setDisplayed] = useState('')
  const [showCursor, setShowCursor] = useState(true)

  useEffect(() => {
    setDisplayed('')
    let i = 0
    const timer = setInterval(() => {
      i++
      setDisplayed(text.slice(0, i))
      if (i >= text.length) clearInterval(timer)
    }, speed)
    return () => clearInterval(timer)
  }, [text, speed])

  useEffect(() => {
    const cursorTimer = setInterval(() => setShowCursor(prev => !prev), 530)
    return () => clearInterval(cursorTimer)
  }, [])

  return (
    <span className={className}>
      {displayed}
      <span className="typewriter-cursor" data-blinking={showCursor}>▋</span>
    </span>
  )
}
