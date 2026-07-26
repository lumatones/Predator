import { CSSProperties, ReactNode } from 'react'

interface SkeletonProps {
  width?: string | number
  height?: string | number
  radius?: string | number
  className?: string
  style?: CSSProperties
  circle?: boolean
}

function px(value: string | number | undefined): string | undefined {
  if (value === undefined) return undefined
  return typeof value === 'number' ? `${value}px` : value
}

export function Skeleton({
  width,
  height,
  radius = 'var(--radius-sm)',
  className = '',
  style,
  circle,
}: SkeletonProps) {
  return (
    <span
      className={`skeleton ${className}`}
      style={{
        width: px(width),
        height: px(height),
        borderRadius: circle ? '50%' : px(radius),
        ...style,
      }}
    />
  )
}

export function SkeletonCard({ children, className = '' }: { children?: ReactNode; className?: string }) {
  return <div className={`skeleton-card ${className}`}>{children}</div>
}

export function SkeletonText({ lines = 3, width = '100%' }: { lines?: number; width?: string | number }) {
  return (
    <div className="skeleton-text" style={{ width: px(width) }}>
      {Array.from({ length: lines }).map((_, i) => (
        <Skeleton key={i} height={12} width={i === lines - 1 ? '70%' : '100%'} />
      ))}
    </div>
  )
}

export function SkeletonCircle({ size = 40 }: { size?: number }) {
  return <Skeleton width={size} height={size} circle />
}

export function SkeletonStatCard({ className = '' }: { className?: string }) {
  return (
    <SkeletonCard className={className}>
      <SkeletonCircle size={40} />
      <Skeleton height={32} width={80} style={{ marginTop: 14, marginBottom: 8 }} />
      <Skeleton height={14} width={140} />
    </SkeletonCard>
  )
}

export function SkeletonTable({ rows = 5, cols = 4 }: { rows?: number; cols?: number }) {
  return (
    <div className="skeleton-table" style={{ '--cols': cols } as CSSProperties}>
      {Array.from({ length: rows }).map((_, rowIdx) => (
        <div key={rowIdx} className="skeleton-row">
          {Array.from({ length: cols }).map((_, colIdx) => (
            <Skeleton key={colIdx} height={14} width={colIdx === 0 ? '80%' : '60%'} />
          ))}
        </div>
      ))}
    </div>
  )
}

export function SkeletonPendingCard() {
  return (
    <SkeletonCard>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
        <SkeletonCircle size={44} />
        <div style={{ flex: 1 }}>
          <Skeleton height={16} width='60%' style={{ marginBottom: 6 }} />
          <Skeleton height={12} width='40%' />
        </div>
      </div>
      <Skeleton height={64} width='100%' radius='var(--radius-sm)' style={{ marginBottom: 16 }} />
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
        <Skeleton height={32} width='100%' />
        <Skeleton height={32} width='100%' />
      </div>
    </SkeletonCard>
  )
}

export function SkeletonTimeline({ items = 5 }: { items?: number }) {
  return (
    <div className="skeleton-timeline">
      {Array.from({ length: items }).map((_, i) => (
        <div key={i} className="skeleton-timeline-item">
          <SkeletonCircle size={24} />
          <div style={{ flex: 1 }}>
            <Skeleton height={16} width='60%' style={{ marginBottom: 8 }} />
            <Skeleton height={12} width='80%' style={{ marginBottom: 4 }} />
            <Skeleton height={12} width='40%' />
          </div>
        </div>
      ))}
    </div>
  )
}
