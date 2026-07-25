import React from "react"

interface Props {
  size?: number
  color?: string
  className?: string
}

const IconLock: React.FC<Props> = ({ size = 20, color = "var(--text-secondary)", className }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <rect x="5" y="11" width="14" height="10" rx="2" opacity="0.85" />
    <path d="M8 11V7C8 4.8 9.8 3 12 3C14.2 3 16 4.8 16 7V11" opacity="0.9">
      <animate attributeName="opacity" values="0.85;1;0.85" dur="3s" repeatCount="indefinite" />
    </path>
    <circle cx="12" cy="16" r="1.5" fill={color} stroke="none" opacity="0.6">
      <animate attributeName="opacity" values="0.4;0.8;0.4" dur="2s" repeatCount="indefinite" />
    </circle>
    <line x1="12" y1="17" x2="12" y2="19" strokeWidth="1" opacity="0.5">
      <animate attributeName="opacity" values="0.3;0.7;0.3" dur="1.5s" repeatCount="indefinite" />
    </line>
  </svg>
)

export default IconLock
