import React from "react"

interface Props {
  size?: number
  color?: string
  className?: string
  animated?: boolean
}

const IconCrosshair: React.FC<Props> = ({ size = 20, color = "var(--text-secondary)", className, animated = false }) => (
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
    {/* Outer ring — subtle pulse */}
    <circle cx="12" cy="12" r="9" opacity="0.6">
      {animated && <animate attributeName="r" values="9;9.8;9" dur="2s" repeatCount="indefinite" />}
    </circle>
    {/* Expanding scan ring */}
    <circle cx="12" cy="12" r="6" strokeWidth="1" opacity="0.4">
      {animated && <animate attributeName="r" values="6;10;6" dur="2s" repeatCount="indefinite" />}
      {animated && <animate attributeName="opacity" values="0.4;0;0.4" dur="2s" repeatCount="indefinite" />}
    </circle>
    {/* Crosshair lines N/S/E/W */}
    <line x1="12" y1="2" x2="12" y2="7" opacity="0.9" />
    <line x1="12" y1="17" x2="12" y2="22" opacity="0.9" />
    <line x1="2" y1="12" x2="7" y2="12" opacity="0.9" />
    <line x1="17" y1="12" x2="22" y2="12" opacity="0.9" />
    {/* Center target dot */}
    <circle cx="12" cy="12" r="2" fill={color} stroke="none">
      {animated && <animate attributeName="opacity" values="0.4;1;0.4" dur="0.8s" repeatCount="indefinite" />}
    </circle>
    {/* Corner brackets */}
    <path d="M4 8L4 4L8 4" strokeWidth="1.2" opacity="0.5" />
    <path d="M20 8L20 4L16 4" strokeWidth="1.2" opacity="0.5" />
    <path d="M4 16L4 20L8 20" strokeWidth="1.2" opacity="0.5" />
    <path d="M20 16L20 20L16 20" strokeWidth="1.2" opacity="0.5" />
  </svg>
)

export default IconCrosshair
