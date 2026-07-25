import React from "react"

interface Props {
  size?: number
  color?: string
  className?: string
}

const IconDNA: React.FC<Props> = ({ size = 20, color = "var(--text-secondary)", className }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <g>
      <animateTransform attributeName="transform" type="rotate" values="0 12 12;360 12 12" dur="6s" repeatCount="indefinite" />
      <path d="M7 4C12 8 12 16 7 20" opacity="0.6" strokeWidth="1.2" />
      <path d="M17 4C12 8 12 16 17 20" opacity="0.6" strokeWidth="1.2" />
    </g>
    <g opacity="0.5">
      <line x1="5.5" y1="6" x2="18.5" y2="6" strokeWidth="0.8" />
      <line x1="5" y1="10" x2="19" y2="10" strokeWidth="0.8" />
      <line x1="5" y1="14" x2="19" y2="14" strokeWidth="0.8" />
      <line x1="5.5" y1="18" x2="18.5" y2="18" strokeWidth="0.8" />
    </g>
    <circle cx="12" cy="12" r="1.5" fill={color} stroke="none" opacity="0.4">
      <animate attributeName="opacity" values="0.3;0.6;0.3" dur="2s" repeatCount="indefinite" />
    </circle>
  </svg>
)

export default IconDNA
