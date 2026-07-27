import { useRef, useMemo, useState, useId, useEffect, useCallback } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { Edges, Torus } from '@react-three/drei'
import { useReducedMotion } from 'framer-motion'
import { Shape, type Mesh, type Group, type Points } from 'three'
import { isWebGLAvailable, getGraphicsPreset, getPresetConfig, type GraphicsPreset } from '../../utils/webgl'

// ═══════════════════════════════════════════════════
// ORBITING PARTICLES
// ═══════════════════════════════════════════════════

function OrbitingParticles({
  color, count = 18, radius = 1.6, speed = 0.4, active,
}: {
  color: string; count?: number; radius?: number; speed?: number; active: boolean
}) {
  const pointsRef = useRef<Points>(null)
  const startAngles = useMemo(() =>
    Array.from({ length: count }, () => Math.random() * Math.PI * 2),
    [count],
  )

  useFrame((state) => {
    if (!pointsRef.current || !active) return
    const t = state.clock.elapsedTime
    // Orbit around Y axis
    pointsRef.current.rotation.y += 0.003 * speed
    pointsRef.current.rotation.x = Math.sin(t * 0.3) * 0.15
    // Pulse opacity
    const mat = pointsRef.current.material as any
    if (mat?.opacity !== undefined) {
      mat.opacity = 0.25 + Math.sin(t * 2) * 0.15
    }
  })

  const positions = useMemo(() => {
    const arr: number[] = []
    for (let i = 0; i < count; i++) {
      const angle = startAngles[i]
      const r = radius + (Math.random() - 0.5) * 0.3
      const y = (Math.random() - 0.5) * 1.6
      arr.push(Math.cos(angle) * r, y, Math.sin(angle) * r)
    }
    return new Float32Array(arr)
  }, [count, radius, startAngles])

  return (
    <points ref={pointsRef}>
      <bufferGeometry>
        <bufferAttribute
          attach="attributes-position"
          args={[positions, 3]}
        />
      </bufferGeometry>
      <pointsMaterial
        color={color}
        size={0.04}
        transparent
        opacity={0.3}
        blending={2}
        depthWrite={false}
      />
    </points>
  )
}

// ═══════════════════════════════════════════════════
// PULSE RINGS (threat detection shockwave)
// ═══════════════════════════════════════════════════

function PulseRings({ active, color, count = 3 }: { active: boolean; color: string; count?: number }) {
  const groupRef = useRef<Group>(null)
  const ringStartTimes = useMemo(() =>
    Array.from({ length: count }, (_, i) => performance.now() + i * 600),
    [count],
  )
  const ringRefs = useRef<(Mesh | null)[]>([])

  useFrame((state) => {
    if (!groupRef.current || !active) return
    const now = performance.now()
    ringRefs.current.forEach((ring, i) => {
      if (!ring) return
      const elapsed = (now - ringStartTimes[i]) / 1000
      const cycle = elapsed % 2.5
      const scale = 0.3 + cycle * 1.5
      ring.scale.setScalar(scale)
      const mat = ring.material as any
      if (mat?.opacity !== undefined) {
        mat.opacity = Math.max(0, 0.45 * (1 - cycle / 2.5))
      }
    })
  })

  return (
    <group ref={groupRef}>
      {Array.from({ length: count }).map((_, i) => (
        <Torus
          key={i}
          ref={(el: Mesh | null) => { ringRefs.current[i] = el }}
          args={[1.3, 0.015, 8, 64]}
          rotation={[Math.PI / 2 + i * 0.4, 0, 0]}
        >
          <meshBasicMaterial
            color={color}
            transparent
            opacity={0}
            depthWrite={false}
          />
        </Torus>
      ))}
    </group>
  )
}

interface ShieldProps {
  accent: string
  light: string
  dark: string
  rotate: boolean
  phase?: 'idle' | 'scanning' | 'done'
  threatCount?: number
  hovered?: boolean
  interactive?: boolean
}

// ═══════════════════════════════════════════════════
// CURSOR TRACKER (tilts scene toward mouse) — unused, kept for reference
// ═══════════════════════════════════════════════════

function Shield({ accent, light, dark, rotate, phase = 'idle', threatCount = 0, hovered = false, interactive = false }: ShieldProps) {
  const meshRef = useRef<Mesh>(null)
  const reducedMotion = useReducedMotion()
  const cursorX = useRef(0)
  const cursorY = useRef(0)
  const cursorTargetX = useRef(0)
  const cursorTargetY = useRef(0)

  // Cursor tracking for interactive mode
  useEffect(() => {
    if (!interactive) return
    const handler = (e: MouseEvent) => {
      cursorTargetX.current = (e.clientX / window.innerWidth - 0.5) * 0.35
      cursorTargetY.current = (e.clientY / window.innerHeight - 0.5) * 0.25
    }
    window.addEventListener('mousemove', handler, { passive: true })
    return () => window.removeEventListener('mousemove', handler)
  }, [interactive])

  const reactiveColor = useMemo(() => {
    if (phase === 'done' && threatCount === 0) return '#22c55e'
    if (phase === 'done' && threatCount > 0) return '#ef4444'
    return accent
  }, [phase, threatCount, accent])

  const reactiveLight = useMemo(() => {
    if (phase === 'done' && threatCount === 0) return '#86efac'
    if (phase === 'done' && threatCount > 0) return '#fca5a5'
    return light
  }, [phase, threatCount, light])

  useFrame((state, delta) => {
    if (meshRef.current && rotate && reducedMotion === false) {
      // Smooth cursor tracking
      if (interactive) {
        cursorX.current += (cursorTargetX.current - cursorX.current) * 0.04
        cursorY.current += (cursorTargetY.current - cursorY.current) * 0.04
      }

      const baseSpeed = hovered ? 1.2 : 0.8
      const speedMultiplier = phase === 'scanning' ? 3.0 : phase === 'done' ? 0.8 : baseSpeed
      meshRef.current.rotation.y += delta * 0.6 * speedMultiplier
      meshRef.current.rotation.x = Math.sin(state.clock.elapsedTime * 0.6) * 0.08 + cursorY.current
      meshRef.current.rotation.z = Math.PI / 6 + cursorX.current

      const hoverAmp = hovered ? 0.02 : 0
      const pulseAmp = (phase === 'scanning' ? 0.08 : phase === 'done' && threatCount === 0 ? 0.06 : 0.05) + hoverAmp
      const pulseSpeed = phase === 'scanning' ? 2.0 : phase === 'done' && threatCount === 0 ? 1.6 : 1.2
      const s = 1 + Math.sin(state.clock.elapsedTime * pulseSpeed) * pulseAmp
      meshRef.current.scale.setScalar(s)
    }
  })

  const shape = useMemo(() => {
    const s = new Shape()
    s.moveTo(0, 1.1)
    s.lineTo(0.85, 0.38)
    s.lineTo(0.85, -0.32)
    s.lineTo(0, -1.1)
    s.lineTo(-0.85, -0.32)
    s.lineTo(-0.85, 0.38)
    s.closePath()
    return s
  }, [])

  return (
    <mesh ref={meshRef} rotation={[0, 0, Math.PI / 6]}>
      <extrudeGeometry
        args={[
          shape,
          { depth: 0.12, bevelEnabled: true, bevelSize: 0.02, bevelThickness: 0.02, bevelSegments: 1 },
        ]}
      />
      <meshStandardMaterial
        color={phase === 'done' ? reactiveColor : dark}
        emissive={reactiveColor}
        emissiveIntensity={phase === 'scanning' ? 1.2 : phase === 'done' ? 0.9 : hovered ? 1.0 : 0.7}
        metalness={0.7}
        roughness={0.25}
      />
      <Edges color={reactiveLight} lineWidth={1.2} threshold={15} />
    </mesh>
  )
}

// ═══════════════════════════════════════════════════
// FALLBACK SVG
// ═══════════════════════════════════════════════════

function LogoFallback({ accent, light, dark, size }: { accent: string; light: string; dark: string; size: number }) {
  const id = useId()
  const gradId = `logo-grad-${id}`
  const glowId = `logo-glow-${id}`
  return (
    <svg width={size} height={size} viewBox="-1.5 -1.5 3 3" style={{ display: 'block' }} aria-hidden="true">
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
      <path d="M 0 -1.35 L 1.1 -0.4 L 1.1 0.5 L 0 1.4 L -1.1 0.5 L -1.1 -0.4 Z"
        fill={`url(#${gradId})`} stroke={light} strokeWidth="0.08" filter={`url(#${glowId})`} opacity="0.95" />
      <path d="M 0 -0.9 L 0.75 -0.1 L 0.75 0.5 L 0 1.05 L -0.75 0.5 L -0.75 -0.1 Z"
        fill="none" stroke={light} strokeWidth="0.05" opacity="0.6" />
    </svg>
  )
}

// ═══════════════════════════════════════════════════
// MAIN COMPONENT
// ═══════════════════════════════════════════════════

interface PredatorLogo3DProps {
  accent: string
  light: string
  dark: string
  size?: number
  preset?: GraphicsPreset | 'auto'
  phase?: 'idle' | 'scanning' | 'done'
  threatCount?: number
  interactive?: boolean
}

export default function PredatorLogo3D({
  accent, light, dark, size = 72, preset = 'auto',
  phase = 'idle', threatCount = 0, interactive = false,
}: PredatorLogo3DProps) {
  const [webglFailed, setWebglFailed] = useState(false)
  const [hovered, setHovered] = useState(false)
  const hasWebGL = useMemo(() => isWebGLAvailable(), [])

  const config = useMemo(() => {
    const p = preset === 'auto' ? getGraphicsPreset() : preset
    return getPresetConfig(p)
  }, [preset])

  const showParticles = config.lightCount >= 2
  const showRings = threatCount > 0 && phase === 'done'
  const pulseColor = threatCount > 0 ? '#ef4444' : accent

  if (!hasWebGL || webglFailed) {
    return (
      <div className="logo-3d logo-3d-fallback" style={{ width: size, height: size, lineHeight: 0 }}>
        <LogoFallback accent={accent} light={light} dark={dark} size={size} />
      </div>
    )
  }

  return (
    <div
      className="logo-3d"
      style={{ width: size, height: size, lineHeight: 0 }}
      onMouseEnter={() => interactive && setHovered(true)}
      onMouseLeave={() => interactive && setHovered(false)}
    >
      <Canvas
        camera={{ position: [0, 0, 5.5], fov: 45 }}
        dpr={[1, Math.max(window.devicePixelRatio || 2, 2)]}
        gl={{ antialias: true, alpha: true }}
        style={{ width: '100%', height: '100%' }}
        onError={() => setWebglFailed(true)}
      >
        <ambientLight intensity={config.lightCount >= 2 ? 0.3 : 0.2} />
        <pointLight position={[4, 4, 6]} intensity={config.lightCount >= 2 ? 1.2 : 0.8} color={light} />
        {config.lightCount >= 2 && <pointLight position={[-4, -2, 2]} intensity={0.4} color={accent} />}

        {/* Orbiting particles */}
        {showParticles && (
          <OrbitingParticles
            color={light}
            count={phase === 'scanning' ? 28 : 16}
            radius={1.8}
            speed={phase === 'scanning' ? 1.5 : 0.6}
            active={true}
          />
        )}

        {/* Pulse rings on threat detection */}
        {showRings && <PulseRings active={showRings} color={pulseColor} count={3} />}

        {/* Main shield */}
        <Shield
          accent={accent} light={light} dark={dark}
          rotate={config.rotate} phase={phase}
          threatCount={threatCount} hovered={hovered}
          interactive={interactive}
        />
      </Canvas>
    </div>
  )
}
