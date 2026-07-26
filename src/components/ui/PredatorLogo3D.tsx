import { useRef, useMemo, useState, useId } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { Edges } from '@react-three/drei'
import { useReducedMotion } from 'framer-motion'
import { Shape, Mesh } from 'three'
import { isWebGLAvailable, getGraphicsPreset, getPresetConfig, type GraphicsPreset } from '../../utils/webgl'

interface ShieldProps {
  accent: string
  light: string
  dark: string
  rotate: boolean
}

function Shield({ accent, light, dark, rotate }: ShieldProps) {
  const meshRef = useRef<Mesh>(null)
  const reducedMotion = useReducedMotion()

  useFrame((state, delta) => {
    if (meshRef.current && rotate && reducedMotion === false) {
      meshRef.current.rotation.y += delta * 0.6
      meshRef.current.rotation.x = Math.sin(state.clock.elapsedTime * 0.6) * 0.08
      // Pulsing scale
      const s = 1 + Math.sin(state.clock.elapsedTime * 1.2) * 0.04
      meshRef.current.scale.setScalar(s)
    }
  })

  const shape = useMemo(() => {
    const s = new Shape()
    s.moveTo(0, 1.4)
    s.lineTo(1.1, 0.5)
    s.lineTo(1.1, -0.4)
    s.lineTo(0, -1.4)
    s.lineTo(-1.1, -0.4)
    s.lineTo(-1.1, 0.5)
    s.closePath()
    return s
  }, [])

  return (
    <mesh ref={meshRef} rotation={[0, 0, Math.PI / 6]}>
      <extrudeGeometry
        args={[
          shape,
          { depth: 0.25, bevelEnabled: true, bevelSize: 0.04, bevelThickness: 0.04, bevelSegments: 2 }
        ]}
      />
      <meshStandardMaterial
        color={dark}
        emissive={accent}
        emissiveIntensity={0.7}
        metalness={0.7}
        roughness={0.25}
      />
      <Edges color={light} lineWidth={2} threshold={15} />
    </mesh>
  )
}

/** Static SVG fallback for devices/browsers without WebGL. */
function LogoFallback({ accent, light, dark, size }: { accent: string; light: string; dark: string; size: number }) {
  const id = useId()
  const gradId = `logo-grad-${id}`
  const glowId = `logo-glow-${id}`

  return (
    <svg
      width={size}
      height={size}
      viewBox="-1.5 -1.5 3 3"
      style={{ display: 'block' }}
      aria-hidden="true"
    >
      <defs>
        <linearGradient id={gradId} x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor={accent} />
          <stop offset="100%" stopColor={dark} />
        </linearGradient>
        <filter id={glowId} x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="0.15" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>
      <path
        d="M 0 -1.35 L 1.1 -0.4 L 1.1 0.5 L 0 1.4 L -1.1 0.5 L -1.1 -0.4 Z"
        fill={`url(#${gradId})`}
        stroke={light}
        strokeWidth="0.08"
        filter={`url(#${glowId})`}
        opacity="0.95"
      />
      <path
        d="M 0 -0.9 L 0.75 -0.1 L 0.75 0.5 L 0 1.05 L -0.75 0.5 L -0.75 -0.1 Z"
        fill="none"
        stroke={light}
        strokeWidth="0.05"
        opacity="0.6"
      />
    </svg>
  )
}

interface PredatorLogo3DProps {
  accent: string
  light: string
  dark: string
  size?: number
  preset?: GraphicsPreset | 'auto'
}

export default function PredatorLogo3D({
  accent,
  light,
  dark,
  size = 72,
  preset = 'auto'
}: PredatorLogo3DProps) {
  const [webglFailed, setWebglFailed] = useState(false)
  const hasWebGL = useMemo(() => isWebGLAvailable(), [])

  const config = useMemo(() => {
    const p = preset === 'auto' ? getGraphicsPreset() : preset
    return getPresetConfig(p)
  }, [preset])

  if (!hasWebGL || webglFailed) {
    return (
      <div className="logo-3d logo-3d-fallback" style={{ width: size, height: size, lineHeight: 0 }}>
        <LogoFallback accent={accent} light={light} dark={dark} size={size} />
      </div>
    )
  }

  return (
    <div className="logo-3d" style={{ width: size, height: size, lineHeight: 0 }}>
      <Canvas
        camera={{ position: [0, 0, 4.5], fov: 45 }}
        dpr={config.dpr}
        gl={{ antialias: config.antialias, alpha: true }}
        style={{ width: '100%', height: '100%' }}
        onError={() => setWebglFailed(true)}
      >
        <ambientLight intensity={config.lightCount >= 2 ? 0.3 : 0.2} />
        <pointLight position={[4, 4, 6]} intensity={config.lightCount >= 2 ? 1.2 : 0.8} color={light} />
        {config.lightCount >= 2 && <pointLight position={[-4, -2, 2]} intensity={0.4} color={accent} />}
        <Shield accent={accent} light={light} dark={dark} rotate={config.rotate} />
      </Canvas>
    </div>
  )
}
