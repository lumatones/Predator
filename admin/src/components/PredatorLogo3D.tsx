import { useRef, useMemo } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import * as THREE from 'three'

function hexagonPoints(radius: number): Float32Array {
  const points: number[] = []
  for (let i = 0; i < 6; i++) {
    const angle = (i * Math.PI) / 3
    points.push(Math.cos(angle) * radius, Math.sin(angle) * radius, 0)
  }
  points.push(points[0], points[1], points[2])
  return new Float32Array(points)
}

function ShieldRing({ radius, color, opacity }: { radius: number; color: string; opacity: number }) {
  const line = useMemo(() => {
    const geometry = new THREE.BufferGeometry()
    geometry.setAttribute('position', new THREE.BufferAttribute(hexagonPoints(radius), 3))
    const material = new THREE.LineBasicMaterial({
      color,
      transparent: true,
      opacity,
    })
    return new THREE.Line(geometry, material)
  }, [radius, color, opacity])

  return <primitive object={line} />
}

function OrbitingParticles() {
  const groupRef = useRef<THREE.Group>(null)

  const points = useMemo(() => {
    const count = 40
    const positions = new Float32Array(count * 3)
    const colors = new Float32Array(count * 3)
    const color = new THREE.Color('#ff3b3b')
    for (let i = 0; i < count; i++) {
      const angle = Math.random() * Math.PI * 2
      const radius = 2 + Math.random() * 1.5
      const y = (Math.random() - 0.5) * 1.5
      positions[i * 3] = Math.cos(angle) * radius
      positions[i * 3 + 1] = y
      positions[i * 3 + 2] = Math.sin(angle) * radius
      colors[i * 3] = color.r
      colors[i * 3 + 1] = color.g
      colors[i * 3 + 2] = color.b
    }
    const geometry = new THREE.BufferGeometry()
    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3))
    geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3))
    const material = new THREE.PointsMaterial({
      size: 0.05,
      transparent: true,
      opacity: 0.6,
      vertexColors: true,
    })
    return new THREE.Points(geometry, material)
  }, [])

  useFrame((_state, delta) => {
    if (groupRef.current) {
      groupRef.current.rotation.y += delta * 0.2
    }
  })

  return (
    <group ref={groupRef}>
      <primitive object={points} />
    </group>
  )
}

function PredatorShield() {
  const groupRef = useRef<THREE.Group>(null)

  useFrame((_state, delta) => {
    if (groupRef.current) {
      groupRef.current.rotation.y += delta * 0.3
    }
  })

  return (
    <group ref={groupRef}>
      <pointLight position={[0, 0, 2]} color="#ff3b3b" intensity={2} distance={10} />
      <pointLight position={[0, 0, -2]} color="#ff6b35" intensity={1.5} distance={10} />
      <ShieldRing radius={1.6} color="#ff3b3b" opacity={0.9} />
      <ShieldRing radius={1.3} color="#ff6b35" opacity={0.7} />
      <ShieldRing radius={1.0} color="#ff3b3b" opacity={0.5} />
      <ShieldRing radius={0.7} color="#ff6b35" opacity={0.4} />
      <OrbitingParticles />
    </group>
  )
}

export default function PredatorLogo3D() {
  return (
    <div style={{ width: '100%', height: '100%' }}>
      <Canvas
        camera={{ position: [0, 0, 5], fov: 50 }}
        dpr={[1, 1.5]}
        gl={{ antialias: true, alpha: true }}
        style={{ background: 'transparent' }}
      >
        <ambientLight intensity={0.3} />
        <PredatorShield />
      </Canvas>
    </div>
  )
}
