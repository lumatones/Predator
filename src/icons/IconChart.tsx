import React from "react"

interface Props {
  size?: number
  color?: string
  className?: string
}

const IconChart: React.FC<Props> = ({ size = 20, color = "var(--text-secondary)", className }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <polyline points="4 18 8 12 12 14 16 8 20 10" opacity="0.9">
      <animate attributeName="opacity" values="0.8;1;0.8" dur="2.5s" repeatCount="indefinite" />
    </polyline>
    <path d="M4 4V20H20" opacity="0.6" />
    <circle cx="8" cy="12" r="1" fill={color} stroke="none" opacity="0.5">
      <animate attributeName="opacity" values="0.3;0.7;0.3" dur="1.5s" repeatCount="indefinite" begin="0s" />
    </circle>
    <circle cx="12" cy="14" r="1" fill={color} stroke="none" opacity="0.5">
      <animate attributeName="opacity" values="0.3;0.7;0.3" dur="1.5s" repeatCount="indefinite" begin="0.4s" />
    </circle>
    <circle cx="16" cy="8" r="1" fill={color} stroke="none" opacity="0.5">
      <animate attributeName="opacity" values="0.3;0.7;0.3" dur="1.5s" repeatCount="indefinite" begin="0.8s" />
    </circle>
  </svg>
)

export default IconChart
