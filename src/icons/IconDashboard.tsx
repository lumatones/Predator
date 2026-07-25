import React from "react"

interface Props {
  size?: number
  color?: string
  className?: string
}

const IconDashboard: React.FC<Props> = ({ size = 20, color = "var(--text-secondary)", className }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <rect x="3" y="3" width="7" height="9" rx="1" opacity="0.9" />
    <rect x="14" y="3" width="7" height="5" rx="1" opacity="0.7" />
    <rect x="14" y="12" width="7" height="9" rx="1" opacity="0.8" />
    <rect x="3" y="16" width="7" height="5" rx="1" opacity="0.6" />
    <line x1="6.5" y1="3" x2="6.5" y2="7" strokeWidth="1.2" opacity="0.5">
      <animate attributeName="y2" values="7;8;7" dur="2s" repeatCount="indefinite" />
    </line>
    <line x1="17.5" y1="3" x2="17.5" y2="5" strokeWidth="1.2" opacity="0.5">
      <animate attributeName="y2" values="5;6;5" dur="1.5s" repeatCount="indefinite" />
    </line>
  </svg>
)

export default IconDashboard
