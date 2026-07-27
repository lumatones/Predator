import React, { useState, useRef, useEffect, useCallback } from 'react'
import { createPortal } from 'react-dom'
import { motion, AnimatePresence } from 'framer-motion'

interface TooltipProps {
  content: string
  children: React.ReactNode
  /** Position relative to children */
  position?: 'top' | 'bottom' | 'left' | 'right'
  /** Delay before showing (ms) */
  delay?: number
  /** Max width of tooltip */
  maxWidth?: number
}

const TOOLTIP_ID = 'predator-tooltip-portal'

function getPortal(): HTMLElement {
  let el = document.getElementById(TOOLTIP_ID)
  if (!el) {
    el = document.createElement('div')
    el.id = TOOLTIP_ID
    document.body.appendChild(el)
  }
  return el
}

export const Tooltip: React.FC<TooltipProps> = ({
  content,
  children,
  position = 'top',
  delay = 400,
  maxWidth = 240,
}) => {
  const [show, setShow] = useState(false)
  const triggerRef = useRef<HTMLSpanElement>(null)
  const [coords, setCoords] = useState({ x: 0, y: 0 })
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const updatePosition = useCallback(() => {
    if (!triggerRef.current) return
    const rect = triggerRef.current.getBoundingClientRect()
    switch (position) {
      case 'top':
        setCoords({ x: rect.left + rect.width / 2, y: rect.top - 8 })
        break
      case 'bottom':
        setCoords({ x: rect.left + rect.width / 2, y: rect.bottom + 8 })
        break
      case 'left':
        setCoords({ x: rect.left - 8, y: rect.top + rect.height / 2 })
        break
      case 'right':
        setCoords({ x: rect.right + 8, y: rect.top + rect.height / 2 })
        break
    }
  }, [position])

  const handleMouseEnter = () => {
    timeoutRef.current = setTimeout(() => {
      updatePosition()
      setShow(true)
    }, delay)
  }

  const handleMouseLeave = () => {
    if (timeoutRef.current) clearTimeout(timeoutRef.current)
    setShow(false)
  }

  const handleFocus = () => {
    updatePosition()
    setShow(true)
  }

  const handleBlur = () => setShow(false)

  useEffect(() => {
    return () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current)
    }
  }, [])

  // Listen to scroll/resize to reposition
  useEffect(() => {
    if (!show) return
    const onUpdate = () => updatePosition()
    window.addEventListener('scroll', onUpdate, true)
    window.addEventListener('resize', onUpdate)
    return () => {
      window.removeEventListener('scroll', onUpdate, true)
      window.removeEventListener('resize', onUpdate)
    }
  }, [show, updatePosition])

  const tooltip = (
    <AnimatePresence>
      {show && (
        <motion.div
          className="predator-tooltip"
          initial={{ opacity: 0, scale: 0.92, y: position === 'bottom' ? -4 : 4 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.92, y: position === 'bottom' ? -4 : 4 }}
          transition={{ duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
          style={{
            position: 'fixed',
            left: coords.x,
            top: coords.y,
            maxWidth,
            transform: position === 'top' || position === 'bottom'
              ? 'translate(-50%, 0)'
              : 'translate(0, -50%)',
            zIndex: 99999,
            pointerEvents: 'none',
          }}
        >
          <div className="tooltip-inner">{content}</div>
          <div className={`tooltip-arrow tooltip-arrow-${position}`} />
        </motion.div>
      )}
    </AnimatePresence>
  )

  return (
    <>
      <span
        ref={triggerRef}
        className="predator-tooltip-trigger"
        onMouseEnter={handleMouseEnter}
        onMouseLeave={handleMouseLeave}
        onFocus={handleFocus}
        onBlur={handleBlur}
        tabIndex={0}
        role="tooltip"
        aria-label={content}
      >
        {children}
      </span>
      {createPortal(tooltip, getPortal())}
    </>
  )
}
