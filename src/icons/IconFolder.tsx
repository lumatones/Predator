import React from "react"

interface Props {
  size?: number
  color?: string
  className?: string
  animated?: boolean
}

const IconFolder: React.FC<Props> = ({ size = 20, color = "var(--text-secondary)", className, animated = false }) => (
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
    {/* Folder body — lid pulse in animated mode */}
    <path d="M2 6C2 4.89543 2.89543 4 4 4H9L11 6H20C21.1046 6 22 6.89543 22 8V18C22 19.1046 21.1046 20 20 20H4C2.89543 20 2 19.1046 2 18V6Z" opacity="0.9">
      {animated && <animate attributeName="opacity" values="0.8;1;0.8" dur="2.5s" repeatCount="indefinite" />}
    </path>
    {/* Scan line — sweeps up and down */}
    <line x1="6" y1="13" x2="18" y2="13" strokeWidth="1" opacity="0.5">
      {animated && <animate attributeName="y1" values="9;16;9" dur="2s" repeatCount="indefinite" />}
      {animated && <animate attributeName="y2" values="9;16;9" dur="2s" repeatCount="indefinite" />}
    </line>
    {/* Magnifying glass — circle pulses */}
    <circle cx="12" cy="12" r="3" strokeWidth="1" opacity="0.6">
      {animated && <animate attributeName="r" values="3;4;3" dur="2s" repeatCount="indefinite" />}
    </circle>
    {/* Magnifying glass handle */}
    <line x1="14.5" y1="14.5" x2="17" y2="17" strokeWidth="1.2" opacity="0.5">
      {animated && <animate attributeName="opacity" values="0.3;0.6;0.3" dur="1.8s" repeatCount="indefinite" />}
    </line>
  </svg>
)

export default IconFolder
