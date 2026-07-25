import React from "react"

interface Props {
  size?: number
  color?: string
  className?: string
  animated?: boolean
}

const IconShield: React.FC<Props> = ({ size = 20, color = "var(--text-secondary)", className, animated = false }) => (
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
    {/* Shield outline */}
    <path d="M12 2L20 5V11C20 16 16 20 12 22C8 20 4 16 4 11V5L12 2Z" opacity="0.9">
      {animated && <animate attributeName="opacity" values="0.8;1;0.8" dur="2.5s" repeatCount="indefinite" />}
    </path>
    {/* Scan line moving vertically */}
    <line x1="7" y1="10" x2="17" y2="10" strokeWidth="0.8" opacity="0.5">
      {animated && <animate attributeName="y1" values="6;17;6" dur="2.5s" repeatCount="indefinite" />}
      {animated && <animate attributeName="y2" values="6;17;6" dur="2.5s" repeatCount="indefinite" />}
    </line>
    {/* Checkmark */}
    <path d="M9 13L11.5 15.5L16 10" strokeWidth="1.2" opacity="0.8">
      {animated && <animate attributeName="opacity" values="0.5;1;0.5" dur="2s" repeatCount="indefinite" />}
    </path>
  </svg>
)

export default IconShield
