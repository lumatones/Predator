import React from "react"

interface Props {
  size?: number
  color?: string
  className?: string
}

const IconStats: React.FC<Props> = ({ size = 20, color = "var(--text-secondary)", className }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <path d="M3 20L9 14L13 17L21 3" opacity="0.9">
      <animate attributeName="opacity" values="0.7;1;0.7" dur="3s" repeatCount="indefinite" />
    </path>
    <polyline points="15 3 21 3 21 9" opacity="0.6">
      <animate attributeName="opacity" values="0.4;0.8;0.4" dur="2.5s" repeatCount="indefinite" />
    </polyline>
    <circle cx="9" cy="14" r="1" fill={color} stroke="none" opacity="0.5">
      <animate attributeName="opacity" values="0.3;0.7;0.3" dur="2s" repeatCount="indefinite" />
    </circle>
    <circle cx="13" cy="17" r="1" fill={color} stroke="none" opacity="0.5">
      <animate attributeName="opacity" values="0.3;0.7;0.3" dur="2s" begin="0.5s" repeatCount="indefinite" />
    </circle>
    <circle cx="21" cy="3" r="1" fill={color} stroke="none" opacity="0.5">
      <animate attributeName="opacity" values="0.3;0.7;0.3" dur="2s" begin="1s" repeatCount="indefinite" />
    </circle>
  </svg>
)

export default IconStats
