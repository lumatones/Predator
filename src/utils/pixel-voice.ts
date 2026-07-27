/**
 * Pixel Voice — retro 8-bit "speech" sounds like old RPGs
 * Uses Web Audio API to synthesize square-wave bursts — no audio files needed.
 */

let audioCtx: AudioContext | null = null

async function getCtx(): Promise<AudioContext> {
  if (!audioCtx) {
    audioCtx = new AudioContext()
  }
  // Resume if suspended (browser autoplay policy)
  if (audioCtx.state === 'suspended') {
    await audioCtx.resume()
  }
  return audioCtx
}

/** Play a single retro "blip" tone */
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

  // Quick attack, quick decay
  gain.gain.setValueAtTime(0, startTime)
  gain.gain.linearRampToValueAtTime(volume, startTime + 0.005)
  gain.gain.linearRampToValueAtTime(0, startTime + duration)

  osc.connect(gain)
  gain.connect(ctx.destination)

  // Clean up nodes after playback to prevent leak
  osc.onended = () => {
    gain.disconnect()
    osc.disconnect()
  }

  osc.start(startTime)
  osc.stop(startTime + duration + 0.01)
}

/**
 * Play a "pixel voice" speech sound — like old RPG dialogue.
 * Each call produces a slightly different sequence of tones.
 * Has a 2.5s cooldown to prevent spam.
 *
 * @param syllables — how many "blips" (3–6 is good for a short phrase)
 * @param pitch — base pitch: 'low', 'mid', 'high'
 */
export async function playPixelVoice(
  syllables: number = 4,
  pitch: 'low' | 'mid' | 'high' = 'mid',
): Promise<void> {
  try {
    const ctx = await getCtx()
    const currentTime = ctx.currentTime

    const baseFreq = { low: 180, mid: 320, high: 520 }[pitch]
    const vol = 0.08 // quiet — don't startle the user

    let time = currentTime
    for (let i = 0; i < syllables; i++) {
      // Vary frequency per "syllable" — retro speech is just random pitches
      const freq = baseFreq + Math.random() * baseFreq * 0.6
      const dur = 0.04 + Math.random() * 0.06 // 40–100ms per blip
      // Alternate square/sawtooth for variety
      const wave: OscillatorType = i % 2 === 0 ? 'square' : 'sawtooth'

      playBlip(ctx, freq, time, dur, vol, wave)

      // Gap between syllables
      time += dur + 0.03 + Math.random() * 0.05
    }

    // Add a subtle low "rumble" at the end for character
    playBlip(ctx, baseFreq * 0.5, time, 0.08, vol * 0.5, 'triangle')
  } catch {
    // Silently fail — audio is a nice-to-have, not critical
  }
}
