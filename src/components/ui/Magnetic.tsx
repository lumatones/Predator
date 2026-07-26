import { useMagnetic } from '../../hooks/useMagnetic'

interface MagneticProps {
  children: React.ReactNode
  strength?: number
  className?: string
}

export function Magnetic({ children, strength = 0.2, className }: MagneticProps) {
  const ref = useMagnetic<HTMLDivElement>(strength)
  return (
    <div ref={ref} className={className} style={{ display: 'block', width: '100%' }}>
      {children}
    </div>
  )
}
