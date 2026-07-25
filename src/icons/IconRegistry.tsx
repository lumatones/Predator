import React from "react"

interface Props {
  size?: number
  color?: string
  className?: string
}

const IconRegistry: React.FC<Props> = ({ size = 20, color = "var(--text-secondary)", className }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <rect x="4" y="2" width="16" height="20" rx="2" opacity="0.85">
      <animate attributeName="opacity" values="0.8;1;0.8" dur="3s" repeatCount="indefinite" />
    </rect>
    <line x1="8" y1="8" x2="16" y2="8" strokeWidth="1" opacity="0.7" />
    <line x1="8" y1="12" x2="16" y2="12" strokeWidth="1" opacity="0.5" />
    <line x1="8" y1="16" x2="13" y2="16" strokeWidth="1" opacity="0.6" />
    <line x1="8" y1="6" x2="16" y2="6" strokeWidth="1.2" opacity="0.4">
      <animate attributeName="opacity" values="0.3;0.6;0.3" dur="2s" repeatCount="indefinite" />
    </line>
  </svg>
)

export default IconRegistry
