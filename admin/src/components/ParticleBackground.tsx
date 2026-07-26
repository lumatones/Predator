import { useMemo, useCallback } from 'react'
import Particles, { ParticlesProvider } from '@tsparticles/react'
import { loadSlim } from '@tsparticles/slim'
import type { ISourceOptions, Engine } from '@tsparticles/engine'

interface ParticleBackgroundProps {
  density?: number
  opacity?: number
  speed?: number
  linkOpacity?: number
  links?: boolean
}

function BackgroundParticles({
  density,
  opacity,
  speed,
  linkOpacity,
  links = true,
}: ParticleBackgroundProps) {
  const options: ISourceOptions = useMemo(
    () => ({
      fullScreen: false,
      fpsLimit: 60,
      particles: {
        number: { value: density, density: { enable: true } },
        color: { value: '#ff3b3b' },
        shape: { type: 'circle' },
        opacity: { value: opacity, random: true },
        size: { value: { min: 1, max: 3 }, random: true },
        move: {
          enable: true,
          speed,
          direction: 'top',
          random: true,
          straight: false,
          outModes: { default: 'out' },
        },
        links: {
          enable: links,
          color: '#ff3b3b',
          opacity: linkOpacity,
          distance: 150,
        },
      },
      interactivity: {
        events: {
          onHover: { enable: true, mode: 'repulse' },
        },
        modes: {
          repulse: { distance: 100, duration: 0.4 },
        },
      },
      detectRetina: true,
      background: { color: 'transparent' },
    }),
    [density, opacity, speed, linkOpacity, links]
  )

  return (
    <Particles
      id="predator-particles"
      options={options}
      style={{
        position: 'absolute',
        inset: 0,
        zIndex: 0,
        pointerEvents: 'none',
      }}
    />
  )
}

export default function ParticleBackground(props: ParticleBackgroundProps) {
  const init = useCallback(async (engine: Engine) => {
    await loadSlim(engine)
  }, [])

  return (
    <ParticlesProvider init={init}>
      <BackgroundParticles {...props} />
    </ParticlesProvider>
  )
}
