import { useCallback, useRef } from 'react'

type SoundName = 'click' | 'swoosh' | 'alarm' | 'ding' | 'tick' | 'complete'

const audioCtxRef = { current: null as AudioContext | null }

function getCtx(): AudioContext | null {
  if (audioCtxRef.current) return audioCtxRef.current
  try {
    const webkitAudioContext = (window as Window & { webkitAudioContext?: typeof AudioContext }).webkitAudioContext
    const AudioContextConstructor = window.AudioContext || webkitAudioContext
    if (!AudioContextConstructor) return null
    audioCtxRef.current = new AudioContextConstructor()
    return audioCtxRef.current
  } catch { return null }
}

// Generate sounds via Web Audio API oscillators + noise
function playSound(ctx: AudioContext, name: SoundName) {
  const now = ctx.currentTime

  switch (name) {
    case 'click': {
      const osc = ctx.createOscillator()
      const gain = ctx.createGain()
      osc.type = 'sine'
      osc.frequency.setValueAtTime(800, now)
      osc.frequency.exponentialRampToValueAtTime(400, now + 0.05)
      gain.gain.setValueAtTime(0.06, now)
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.06)
      osc.connect(gain).connect(ctx.destination)
      osc.start(now); osc.stop(now + 0.06)
      break
    }
    case 'swoosh': {
      const bufferSize = ctx.sampleRate * 0.12
      const buffer = ctx.createBuffer(1, bufferSize, ctx.sampleRate)
      const data = buffer.getChannelData(0)
      for (let i = 0; i < bufferSize; i++) {
        const t = i / ctx.sampleRate
        data[i] = (Math.random() * 2 - 1) * Math.max(0, 1 - t / 0.12) * 0.03
          * Math.sin(t * 2000 + Math.sin(t * 5000) * 3)
      }
      const src = ctx.createBufferSource()
      const gain = ctx.createGain()
      const filter = ctx.createBiquadFilter()
      filter.type = 'bandpass'
      filter.frequency.setValueAtTime(3000, now)
      filter.Q.setValueAtTime(2, now)
      gain.gain.setValueAtTime(0.04, now)
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.12)
      src.buffer = buffer
      src.connect(filter).connect(gain).connect(ctx.destination)
      src.start(now)
      break
    }
    case 'alarm': {
      for (let i = 0; i < 3; i++) {
        const osc = ctx.createOscillator()
        const gain = ctx.createGain()
        const t = now + i * 0.18
        osc.type = 'square'
        osc.frequency.setValueAtTime(200, t)
        osc.frequency.exponentialRampToValueAtTime(600, t + 0.08)
        gain.gain.setValueAtTime(0, t)
        gain.gain.linearRampToValueAtTime(0.05, t + 0.01)
        gain.gain.exponentialRampToValueAtTime(0.001, t + 0.15)
        osc.connect(gain).connect(ctx.destination)
        osc.start(t); osc.stop(t + 0.15)
      }
      break
    }
    case 'ding': {
      const osc = ctx.createOscillator()
      const gain = ctx.createGain()
      osc.type = 'sine'
      osc.frequency.setValueAtTime(880, now)
      osc.frequency.setValueAtTime(1100, now + 0.05)
      gain.gain.setValueAtTime(0.05, now)
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.25)
      osc.connect(gain).connect(ctx.destination)
      osc.start(now); osc.stop(now + 0.25)
      break
    }
    case 'tick': {
      const osc = ctx.createOscillator()
      const gain = ctx.createGain()
      osc.type = 'sine'
      osc.frequency.setValueAtTime(600, now)
      gain.gain.setValueAtTime(0.03, now)
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.03)
      osc.connect(gain).connect(ctx.destination)
      osc.start(now); osc.stop(now + 0.03)
      break
    }
    case 'complete': {
      const notes = [523, 659, 784, 1047]
      notes.forEach((freq, i) => {
        const osc = ctx.createOscillator()
        const gain = ctx.createGain()
        const t = now + i * 0.1
        osc.type = 'sine'
        osc.frequency.setValueAtTime(freq, t)
        gain.gain.setValueAtTime(0, t)
        gain.gain.linearRampToValueAtTime(0.04, t + 0.02)
        gain.gain.exponentialRampToValueAtTime(0.001, t + 0.2)
        osc.connect(gain).connect(ctx.destination)
        osc.start(t); osc.stop(t + 0.2)
      })
      break
    }
  }
}

export function useSound() {
  const enabledRef = useRef(true)

  const play = useCallback((name: SoundName) => {
    if (!enabledRef.current) return
    const ctx = getCtx()
    if (!ctx) return
    // Resume context if suspended (browser autoplay policy)
    if (ctx.state === 'suspended') ctx.resume().catch(() => {})
    playSound(ctx, name)
  }, [])

  const setEnabled = useCallback((enabled: boolean) => {
    enabledRef.current = enabled
  }, [])

  return { play, setEnabled }
}
