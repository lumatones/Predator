import React from "react"

interface Props {
  size?: number
  color?: string
  className?: string
  animated?: boolean
}

const IconUSB: React.FC<Props> = ({ size = 20, color = "var(--text-secondary)", className, animated = false }) => (
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
    {/* USB plug trapezoid */}
    <path d="M10 2L14 2L15 9L9 9L10 2Z" opacity="0.9" />
    {/* Connector body */}
    <rect x="8" y="9" width="8" height="4" rx="1" opacity="0.8" />
    {/* Base */}
    <rect x="7" y="13" width="10" height="3" rx="0.5" opacity="0.7" />
    {/* Signal lines — cascading with staggered delays */}
    <line x1="4" y1="10" x2="8" y2="10" strokeWidth="1" opacity="0.5">
      {animated && <animate attributeName="opacity" values="0.4;1;0" dur="1.5s" repeatCount="indefinite" />}
    </line>
    <line x1="3" y1="13" x2="7" y2="13" strokeWidth="1" opacity="0.3">
      {animated && <animate attributeName="opacity" values="0.3;0.8;0.3" dur="2s" repeatCount="indefinite" begin="0.3s" />}
    </line>
    <line x1="5" y1="16" x2="7" y2="16" strokeWidth="1" opacity="0.4">
      {animated && <animate attributeName="opacity" values="0.4;0.9;0" dur="1.8s" repeatCount="indefinite" begin="0.6s" />}
    </line>
    {/* LED indicator */}
    <circle cx="17" cy="6" r="1.5" fill={color} stroke="none">
      {animated && <animate attributeName="opacity" values="0.2;1;0.2" dur="1s" repeatCount="indefinite" />}
    </circle>
  </svg>
)

export default IconUSB
