/**
 * Predator — Lottie-like animated icons using framer-motion + SVG
 * No external Lottie dependencies needed.
 */
import { motion } from 'framer-motion'
import React from 'react'

// ── Scanning Shield (pulsing + radar sweep) ──

export const AnimatedShield: React.FC<{ size?: number; accent?: string; phase?: 'scanning' | 'analyzing' | 'done' }> = ({
  size = 48,
  accent = '#ef4444',
  phase = 'scanning',
}) => {
  return (
    <svg width={size} height={size} viewBox="0 0 100 100" fill="none">
      {/* Outer ring pulse */}
      <motion.circle
        cx="50" cy="50" r="45"
        stroke={accent}
        strokeWidth="1.5"
        fill="none"
        animate={{
          r: [45, 48, 45],
          opacity: [0.4, 0.15, 0.4],
        }}
        transition={{ duration: 2, repeat: Infinity, ease: 'easeInOut' }}
      />
      <motion.circle
        cx="50" cy="50" r="40"
        stroke={accent}
        strokeWidth="1"
        fill="none"
        animate={{
          r: [40, 43, 40],
          opacity: [0.3, 0.1, 0.3],
        }}
        transition={{ duration: 2, repeat: Infinity, ease: 'easeInOut', delay: 0.5 }}
      />
      {/* Shield shape */}
      <motion.path
        d="M50 15 L50 15 C35 25 20 40 20 55 C20 68 28 75 50 85 C72 75 80 68 80 55 C80 40 65 25 50 15Z"
        fill={accent}
        fillOpacity={0.15}
        stroke={accent}
        strokeWidth="2"
        animate={{
          scale: [1, 1.03, 1],
          fillOpacity: [0.15, 0.22, 0.15],
        }}
        transition={{ duration: 1.5, repeat: Infinity, ease: 'easeInOut' }}
      />
      {/* Radar sweep line */}
      {phase === 'scanning' && (
        <motion.line
          x1="50" y1="50"
          x2="50" y2="20"
          stroke={accent}
          strokeWidth="1.5"
          strokeLinecap="round"
          animate={{ rotate: [0, 360] }}
          transition={{ duration: 3, repeat: Infinity, ease: 'linear' }}
          style={{ transformOrigin: '50px 50px' }}
        />
      )}
      {/* Center eye */}
      <motion.circle
        cx="50" cy="52" r="5"
        fill={accent}
        animate={{
          opacity: [0.5, 1, 0.5],
          r: [5, 6, 5],
        }}
        transition={{ duration: 1.2, repeat: Infinity, ease: 'easeInOut' }}
      />
    </svg>
  )
}

// ── Animated Checkmark (success) ──

export const AnimatedCheckmark: React.FC<{ size?: number; color?: string }> = ({
  size = 64,
  color = '#22c55e',
}) => {
  return (
    <motion.svg width={size} height={size} viewBox="0 0 100 100" fill="none">
      {/* Circle background */}
      <motion.circle
        cx="50" cy="50" r="40"
        stroke={color}
        strokeWidth="2.5"
        fill="none"
        initial={{ pathLength: 0, opacity: 0 }}
        animate={{ pathLength: 1, opacity: 1 }}
        transition={{ duration: 0.6, ease: 'easeOut' }}
      />
      {/* Checkmark */}
      <motion.path
        d="M30 52 L44 66 L70 36"
        stroke={color}
        strokeWidth="4"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
        initial={{ pathLength: 0 }}
        animate={{ pathLength: 1 }}
        transition={{ duration: 0.4, delay: 0.3, ease: 'easeOut' }}
      />
      {/* Sparkle particles */}
      {[0, 1, 2, 3, 4].map(i => (
        <motion.circle
          key={i}
          cx={50 + Math.cos((i * 72) * Math.PI / 180) * 38}
          cy={50 + Math.sin((i * 72) * Math.PI / 180) * 38}
          r={2.5}
          fill={color}
          initial={{ scale: 0, opacity: 0 }}
          animate={{
            scale: [0, 1.5, 0],
            opacity: [0, 0.8, 0],
          }}
          transition={{
            duration: 1.2,
            delay: 0.6 + i * 0.1,
            repeat: Infinity,
            repeatDelay: 2,
            ease: 'easeOut',
          }}
        />
      ))}
    </motion.svg>
  )
}

// ── Animated Cross (error/danger) ──

export const AnimatedCross: React.FC<{ size?: number; color?: string }> = ({
  size = 64,
  color = '#ef4444',
}) => {
  return (
    <motion.svg width={size} height={size} viewBox="0 0 100 100" fill="none">
      <motion.circle
        cx="50" cy="50" r="40"
        stroke={color}
        strokeWidth="2.5"
        fill="none"
        initial={{ pathLength: 0 }}
        animate={{ pathLength: 1 }}
        transition={{ duration: 0.4, ease: 'easeOut' }}
      />
      <motion.path
        d="M33 33 L67 67"
        stroke={color}
        strokeWidth="4"
        strokeLinecap="round"
        initial={{ pathLength: 0 }}
        animate={{ pathLength: 1 }}
        transition={{ duration: 0.3, delay: 0.2, ease: 'easeOut' }}
      />
      <motion.path
        d="M67 33 L33 67"
        stroke={color}
        strokeWidth="4"
        strokeLinecap="round"
        initial={{ pathLength: 0 }}
        animate={{ pathLength: 1 }}
        transition={{ duration: 0.3, delay: 0.3, ease: 'easeOut' }}
      />
      {/* Pulse ring */}
      <motion.circle
        cx="50" cy="50" r="40"
        stroke={color}
        strokeWidth="1"
        fill="none"
        animate={{
          r: [40, 55, 40],
          opacity: [0.3, 0, 0.3],
        }}
        transition={{ duration: 2, repeat: Infinity, ease: 'easeInOut', delay: 0.5 }}
      />
    </motion.svg>
  )
}

// ── Scanning Dots (loader) ──

export const ScanningDots: React.FC<{ size?: number; color?: string; count?: number }> = ({
  size = 32,
  color = '#ef4444',
  count = 3,
}) => {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6, height: size }}>
      {Array.from({ length: count }).map((_, i) => (
        <motion.div
          key={i}
          style={{
            width: Math.max(6, size / 5),
            height: Math.max(6, size / 5),
            borderRadius: '50%',
            backgroundColor: color,
          }}
          animate={{
            scale: [1, 1.6, 1],
            opacity: [0.4, 1, 0.4],
          }}
          transition={{
            duration: 1.2,
            repeat: Infinity,
            delay: i * 0.2,
            ease: 'easeInOut',
          }}
        />
      ))}
    </div>
  )
}

// ── Spinner Ring ──

export const SpinnerRing: React.FC<{ size?: number; color?: string; strokeWidth?: number }> = ({
  size = 32,
  color = '#ef4444',
  strokeWidth = 2.5,
}) => {
  const radius = (size / 2) - strokeWidth
  const circumference = 2 * Math.PI * radius
  return (
    <motion.svg
      width={size}
      height={size}
      viewBox={`0 0 ${size} ${size}`}
      animate={{ rotate: 360 }}
      transition={{ duration: 1.2, repeat: Infinity, ease: 'linear' }}
    >
      <circle
        cx={size / 2}
        cy={size / 2}
        r={radius}
        fill="none"
        stroke={color}
        strokeWidth={strokeWidth}
        strokeLinecap="round"
        strokeDasharray={`${circumference * 0.65} ${circumference * 0.35}`}
        opacity={0.3}
      />
      <motion.circle
        cx={size / 2}
        cy={size / 2}
        r={radius}
        fill="none"
        stroke={color}
        strokeWidth={strokeWidth}
        strokeLinecap="round"
        strokeDasharray={`${circumference * 0.25} ${circumference * 0.75}`}
      />
    </motion.svg>
  )
}
