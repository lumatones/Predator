import React from "react"

interface Props {
  size?: number
  color?: string
  className?: string
  animated?: boolean
}

const IconGear: React.FC<Props> = ({ size = 20, color = "var(--text-secondary)", className, animated = false }) => (
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
    <g>
      {animated && <animateTransform attributeName="transform" type="rotate" values="0 12 12;360 12 12" dur="3s" repeatCount="indefinite" />}
      <circle cx="12" cy="12" r="7" opacity="0.9" />
      {/* Gear teeth via dasharray */}
      <circle cx="12" cy="12" r="7" strokeWidth="2.2" strokeDasharray="2.5 3.0" opacity="0.8" />
      {/* Inner ring */}
      <circle cx="12" cy="12" r="4.5" opacity="0.6" />
    </g>
    {/* Center dot — pulse */}
    <circle cx="12" cy="12" r="1.5" fill={color} stroke="none">
      {animated && <animate attributeName="opacity" values="0.3;1;0.3" dur="1.2s" repeatCount="indefinite" />}
    </circle>
  </svg>
)

export default IconGear
