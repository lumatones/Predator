import { useCallback, useMemo } from 'react'
import { useReducedMotion } from 'framer-motion'
import Particles, { ParticlesProvider } from '@tsparticles/react'
import { loadSlim } from '@tsparticles/slim'
import type { Engine, ISourceOptions } from '@tsparticles/engine'

interface ParticleBackgroundProps {
  accentColor?: string
  lightColor?: string
}

export default function ParticleBackground({
  accentColor = '#ff4444',
  lightColor = '#ff6b35',
}: ParticleBackgroundProps) {
  const reducedMotion = useReducedMotion()
  // Treat the initial `null` value as reduced motion to avoid a flash of
  // animation for users who have requested reduced motion at the OS level.
  const isReduced = reducedMotion !== false

  if (isReduced) {
    return (
      <div
        style={{
          position: 'absolute',
          inset: 0,
          zIndex: 0,
          background: `radial-gradient(circle at 30% 30%, ${accentColor}10, transparent 50%),
                       radial-gradient(circle at 70% 70%, ${lightColor}08, transparent 50%)`,
        }}
      />
    )
  }

  const init = useCallback(async (engine: Engine) => {
    await loadSlim(engine)
  }, [])

  const options: ISourceOptions = useMemo(() => ({
    fullScreen: false,
    fpsLimit: 60,
    particles: {
      number: { value: 90, density: { enable: true } },
      color: { value: [accentColor, lightColor, '#ffffff'] },
      shape: { type: 'circle' },
      opacity: {
        value: { min: 0.15, max: 0.45 },
        random: true,
        animation: { enable: true, speed: 0.3, sync: false },
      },
      size: { value: { min: 1, max: 3.5 }, random: true },
      move: {
        enable: true,
        speed: 0.6,
        direction: 'none',
        random: true,
        straight: false,
        outModes: { default: 'bounce' },
      },
      links: {
        enable: true,
        color: accentColor,
        opacity: 0.12,
        distance: 160,
        width: 1,
      },
    },
    interactivity: {
      events: {
        onHover: { enable: true, mode: 'repulse' },
      },
      modes: {
        repulse: { distance: 120, duration: 0.4 },
      },
    },
    detectRetina: true,
    background: { color: 'transparent' },
  }), [accentColor, lightColor])

  return (
    <ParticlesProvider init={init}>
      <Particles
        id="predator-particles"
        options={options}
        style={{
          position: 'absolute',
          inset: 0,
          zIndex: 0,
        }}
      />
    </ParticlesProvider>
  )
}
