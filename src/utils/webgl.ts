export type GraphicsPreset = 'low' | 'medium' | 'high'

/** Returns true if a WebGL context can be created in this browser. */
export function isWebGLAvailable(): boolean {
  if (typeof window === 'undefined' || typeof document === 'undefined') return false
  try {
    const canvas = document.createElement('canvas')
    const gl =
      canvas.getContext('webgl2') ||
      canvas.getContext('webgl') ||
      canvas.getContext('experimental-webgl')
    return !!gl
  } catch {
    return false
  }
}

/** Detect a sensible graphics preset for the current device. */
export function getGraphicsPreset(): GraphicsPreset {
  if (typeof window === 'undefined') return 'medium'

  const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches
  if (prefersReduced) return 'low'

  const dpr = window.devicePixelRatio || 1
  const cores = navigator.hardwareConcurrency || 2
  const memory = (navigator as Navigator & { deviceMemory?: number }).deviceMemory || 4

  if (dpr >= 2.5 && cores >= 8 && memory >= 8) return 'high'
  if (dpr >= 2 && cores >= 4 && memory >= 4) return 'medium'
  return 'low'
}

export interface PresetConfig {
  dpr: [number, number]
  antialias: boolean
  rotate: boolean
  lightCount: number
}

/** Map a graphics preset to concrete Three/Canvas settings. */
export function getPresetConfig(preset: GraphicsPreset): PresetConfig {
  switch (preset) {
    case 'high':
      return { dpr: [1, 2.5] as [number, number], antialias: true, rotate: true, lightCount: 3 }
    case 'medium':
      return { dpr: [1, 2] as [number, number], antialias: true, rotate: true, lightCount: 2 }
    case 'low':
    default:
      return { dpr: [1, 1] as [number, number], antialias: false, rotate: false, lightCount: 1 }
  }
}
