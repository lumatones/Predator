import React from "react"

interface Props {
  size?: number
  color?: string
  className?: string
  animated?: boolean
}

const IconGlobe: React.FC<Props> = ({ size = 20, color = "var(--text-secondary)", className, animated = false }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    stroke={color}
    strokeWidth="1.5"
    strokeLinecap="round"
    strokeLinejoin="round"
    className={className}
  >
    {/* Outer globe */}
    <circle cx="12" cy="12" r="10" opacity="0.8" />
    {/* Rotating orbit line — latitude */}
    <ellipse cx="12" cy="12" rx="4" ry="10" opacity="0.6">
      {animated && <animateTransform attributeName="transform" type="rotate" values="0 12 12;360 12 12" dur="6s" repeatCount="indefinite" />}
    </ellipse>
    {/* Equator line */}
    <line x1="2" y1="12" x2="22" y2="12" opacity="0.5" />
    {/* Center dot */}
    <circle cx="12" cy="12" r="2" fill={color} stroke="none" opacity="0.4">
      {animated && <animate attributeName="opacity" values="0.3;0.6;0.3" dur="2s" repeatCount="indefinite" />}
    </circle>
  </svg>
)

export default IconGlobe
