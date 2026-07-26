import React from 'react'

interface SkeletonProps {
  /** Width as a CSS value (e.g. "100%", "120px", "2rem") */
  width?: string
  /** Height as a CSS value */
  height?: string
  /** CSS border-radius */
  radius?: string
  className?: string
  style?: React.CSSProperties
}

/** Base shimmer skeleton block. */
export const Skeleton: React.FC<SkeletonProps> = ({
  width = '100%',
  height = '1em',
  radius = 'var(--radius-md)',
  className = '',
  style,
}) => {
  return (
    <span
      className={`skeleton ${className}`.trim()}
      style={{ width, height, borderRadius: radius, ...style }}
      aria-hidden="true"
    />
  )
}

interface SkeletonCardProps {
  lines?: number
  className?: string
}

/** Card-shaped skeleton with a header circle and several text lines. */
export const SkeletonCard: React.FC<SkeletonCardProps> = ({ lines = 3, className = '' }) => {
  return (
    <div className={`skeleton-card ${className}`.trim()} aria-hidden="true">
      <div className="skeleton-card-header">
        <Skeleton width="48px" height="48px" radius="var(--radius-md)" />
        <div className="skeleton-card-title">
          <Skeleton width="70%" height="16px" />
          <Skeleton width="50%" height="12px" />
        </div>
      </div>
      <div className="skeleton-card-body">
        {Array.from({ length: lines }).map((_, i) => (
          <Skeleton key={i} width={i === lines - 1 ? '60%' : '100%'} height="12px" />
        ))}
      </div>
    </div>
  )
}

interface SkeletonTextProps {
  lines?: number
  className?: string
}

export const SkeletonText: React.FC<SkeletonTextProps> = ({ lines = 2, className = '' }) => {
  return (
    <div className={`skeleton-text ${className}`.trim()} aria-hidden="true">
      {Array.from({ length: lines }).map((_, i) => (
        <Skeleton key={i} width={i === lines - 1 ? '70%' : '100%'} height="1em" />
      ))}
    </div>
  )
}

interface SkeletonTableProps {
  rows?: number
  cols?: number
  className?: string
}

export const SkeletonTable: React.FC<SkeletonTableProps> = ({ rows = 5, cols = 4, className = '' }) => {
  return (
    <div className={`skeleton-table ${className}`.trim()} aria-hidden="true">
      <div className="skeleton-table-row header" style={{ gridTemplateColumns: `repeat(${cols}, 1fr)` }}>
        {Array.from({ length: cols }).map((_, i) => (
          <Skeleton key={i} width="80%" height="12px" />
        ))}
      </div>
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="skeleton-table-row" style={{ gridTemplateColumns: `repeat(${cols}, 1fr)` }}>
          {Array.from({ length: cols }).map((__, c) => (
            <Skeleton key={c} width={c === 0 ? '40%' : c === cols - 1 ? '60%' : '80%'} height="12px" />
          ))}
        </div>
      ))}
    </div>
  )
}

interface SkeletonGaugeProps {
  count?: number
  className?: string
}

export const SkeletonGauge: React.FC<SkeletonGaugeProps> = ({ count = 3, className = '' }) => {
  return (
    <div className={`skeleton-gauges ${className}`.trim()} aria-hidden="true">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="skeleton-gauge">
          <Skeleton width="80px" height="80px" radius="50%" />
          <Skeleton width="60px" height="14px" />
          <Skeleton width="40px" height="10px" />
        </div>
      ))}
    </div>
  )
}

export default Skeleton
