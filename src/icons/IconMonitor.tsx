import React from "react"

interface Props {
  size?: number
  color?: string
  className?: string
}

const IconMonitor: React.FC<Props> = ({ size = 20, color = "var(--text-secondary)", className }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <rect x="2" y="3" width="20" height="14" rx="2" opacity="0.9">
      <animate attributeName="opacity" values="0.85;1;0.85" dur="3s" repeatCount="indefinite" />
    </rect>
    <line x1="8" y1="21" x2="16" y2="21" opacity="0.7" />
    <line x1="12" y1="17" x2="12" y2="21" opacity="0.6" />
    <circle cx="12" cy="10" r="3" strokeWidth="1" opacity="0.5">
      <animate attributeName="r" values="3;3.5;3" dur="2s" repeatCount="indefinite" />
    </circle>
  </svg>
)

export default IconMonitor
