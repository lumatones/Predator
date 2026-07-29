/**
 * Pixel Voice — retro 8-bit "speech" sounds + horror SFX
 * Uses Web Audio API to synthesize sounds — no audio files needed.
 *
 * Exported functions:
 *  playPixelVoice(syllables, pitch)  — RPG dialogue blips
 *  playCreepyChord()                 — dissonant horror chord (scary mode trigger)
 *  playGlitch()                      — short digital glitch burst
 *  playAlarm()                       — rising alarm for countdown
 *  playRumble()                      — low horror rumble for red screen
 *  playJingle()                      — playful "just kidding" ascending blip
 */

let audioCtx: AudioContext | null = null

async function getCtx(): Promise<AudioContext> {
  if (!audioCtx) {
    audioCtx = new AudioContext()
  }
  if (audioCtx.state === 'suspended') {
    await audioCtx.resume()
  }
  return audioCtx
}

// ── Primitive builders ──

function playBlip(
  ctx: AudioContext,
  frequency: number,
  startTime: number,
  duration: number,
  volume: number,
  type: OscillatorType = 'square',
): void {
  const osc = ctx.createOscillator()
  const gain = ctx.createGain()

  osc.type = type
  osc.frequency.setValueAtTime(frequency, startTime)

  gain.gain.setValueAtTime(0, startTime)
  gain.gain.linearRampToValueAtTime(volume, startTime + 0.005)
  gain.gain.linearRampToValueAtTime(0, startTime + duration)

  osc.connect(gain)
  gain.connect(ctx.destination)

  osc.onended = () => { gain.disconnect(); osc.disconnect() }
  osc.start(startTime)
  osc.stop(startTime + duration + 0.01)
}

function playTone(
  ctx: AudioContext,
  frequency: number,
  startTime: number,
  duration: number,
  volume: number,
  type: OscillatorType = 'sine',
  endFrequency?: number,
): void {
  const osc = ctx.createOscillator()
  const gain = ctx.createGain()

  osc.type = type
  osc.frequency.setValueAtTime(frequency, startTime)
  if (endFrequency !== undefined) {
    osc.frequency.exponentialRampToValueAtTime(endFrequency, startTime + duration)
  }

  gain.gain.setValueAtTime(0, startTime)
  gain.gain.linearRampToValueAtTime(volume, startTime + 0.02)
  gain.gain.exponentialRampToValueAtTime(0.0001, startTime + duration)

  osc.connect(gain)
  gain.connect(ctx.destination)

  osc.onended = () => { gain.disconnect(); osc.disconnect() }
  osc.start(startTime)
  osc.stop(startTime + duration + 0.05)
}

function playNoise(
  ctx: AudioContext,
  startTime: number,
  duration: number,
  volume: number,
  filterFreq = 800,
): void {
  const bufferSize = Math.ceil(ctx.sampleRate * duration)
  const buffer = ctx.createBuffer(1, bufferSize, ctx.sampleRate)
  const data = buffer.getChannelData(0)
  for (let i = 0; i < bufferSize; i++) {
    data[i] = (Math.random() * 2 - 1)
  }

  const source = ctx.createBufferSource()
  source.buffer = buffer

  const filter = ctx.createBiquadFilter()
  filter.type = 'bandpass'
  filter.frequency.value = filterFreq
  filter.Q.value = 0.8

  const gain = ctx.createGain()
  gain.gain.setValueAtTime(0, startTime)
  gain.gain.linearRampToValueAtTime(volume, startTime + 0.01)
  gain.gain.linearRampToValueAtTime(0, startTime + duration)

  source.connect(filter)
  filter.connect(gain)
  gain.connect(ctx.destination)

  source.onended = () => { filter.disconnect(); gain.disconnect(); source.disconnect() }
  source.start(startTime)
}

// ── Cooldown tracker ──

const cooldowns: Record<string, number> = {}
function isOnCooldown(key: string, ms: number): boolean {
  const now = Date.now()
  if (cooldowns[key] && now - cooldowns[key] < ms) return true
  cooldowns[key] = now
  return false
}

// ═══════════════════════════════════════════════════════
//  PUBLIC API
// ═══════════════════════════════════════════════════════

export async function playPixelVoice(
  syllables: number = 4,
  pitch: 'low' | 'mid' | 'high' = 'mid',
): Promise<void> {
  if (isOnCooldown('pixelVoice', 1500)) return
  try {
    const ctx = await getCtx()
    const currentTime = ctx.currentTime

    const baseFreq = { low: 180, mid: 320, high: 520 }[pitch]
    const vol = 0.08

    let time = currentTime
    for (let i = 0; i < syllables; i++) {
      const freq = baseFreq + Math.random() * baseFreq * 0.6
      const dur = 0.04 + Math.random() * 0.06
      const wave: OscillatorType = i % 2 === 0 ? 'square' : 'sawtooth'
      playBlip(ctx, freq, time, dur, vol, wave)
      time += dur + 0.03 + Math.random() * 0.05
    }

    playBlip(ctx, baseFreq * 0.5, time, 0.08, vol * 0.5, 'triangle')
  } catch {
    // Audio is a nice-to-have
  }
}

export async function playCreepyChord(): Promise<void> {
  if (isOnCooldown('creepyChord', 2000)) return
  try {
    const ctx = await getCtx()
    const t = ctx.currentTime

    playTone(ctx, 60,   t,        2.5, 0.06, 'sawtooth', 55)
    playTone(ctx, 85,   t + 0.05, 2.2, 0.05, 'square',  80)
    playTone(ctx, 130,  t + 0.1,  1.8, 0.04, 'triangle', 90)
    playTone(ctx, 35, t, 0.4, 0.09, 'sine', 20)
    playNoise(ctx, t, 0.3, 0.05, 200)
  } catch {}
}

export async function playGlitch(): Promise<void> {
  if (isOnCooldown('glitch', 800)) return
  try {
    const ctx = await getCtx()
    const t = ctx.currentTime

    for (let i = 0; i < 12; i++) {
      const freq = 800 + Math.random() * 2400
      const start = t + i * 0.025 + Math.random() * 0.01
      const dur = 0.015 + Math.random() * 0.025
      const wave: OscillatorType = Math.random() > 0.5 ? 'square' : 'sawtooth'
      playBlip(ctx, freq, start, dur, 0.04 + Math.random() * 0.04, wave)
    }

    playTone(ctx, 1200, t, 0.18, 0.06, 'sawtooth', 80)
  } catch {}
}

export async function playAlarm(): Promise<void> {
  if (isOnCooldown('alarm', 3000)) return
  try {
    const ctx = await getCtx()
    const t = ctx.currentTime

    for (let i = 0; i < 4; i++) {
      const isHigh = i % 2 === 0
      const freq = isHigh ? 880 : 660
      const vol = 0.04 + i * 0.008
      playBlip(ctx, freq, t + i * 0.22, 0.18, vol, 'square')
    }
  } catch {}
}

export async function playRumble(): Promise<void> {
  if (isOnCooldown('rumble', 4000)) return
  try {
    const ctx = await getCtx()
    const t = ctx.currentTime

    playTone(ctx, 28, t, 3.5, 0.12, 'sine', 22)
    playTone(ctx, 42, t + 0.1, 3.0, 0.07, 'triangle', 35)
    playTone(ctx, 80, t, 1.2, 0.05, 'sawtooth', 60)
    playNoise(ctx, t, 0.6, 0.04, 300)
    playNoise(ctx, t + 1.2, 0.4, 0.03, 200)
    playNoise(ctx, t + 2.4, 0.5, 0.04, 250)
  } catch {}
}

export async function playJingle(): Promise<void> {
  if (isOnCooldown('jingle', 1000)) return
  try {
    const ctx = await getCtx()
    const t = ctx.currentTime

    const notes = [261.63, 329.63, 392.0, 523.25, 392.0, 523.25]
    notes.forEach((freq, i) => {
      playBlip(ctx, freq, t + i * 0.08, 0.12, 0.07, i % 2 === 0 ? 'square' : 'triangle')
    })
  } catch {}
}
