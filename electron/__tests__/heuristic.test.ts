import { describe, it, expect } from 'vitest'
import { calculateEntropy, riskScoreToLevel, matchKnownCheat } from '../heuristic'

// ═══════════════════════════════════════════════════════
// calculateEntropy
// ═══════════════════════════════════════════════════════

describe('calculateEntropy', () => {
  it('returns 0 for empty buffer', () => {
    expect(calculateEntropy(Buffer.alloc(0))).toBe(0)
  })

  it('returns 0 for null/undefined input', () => {
    expect(calculateEntropy(null as unknown as Buffer)).toBe(0)
    expect(calculateEntropy(undefined as unknown as Buffer)).toBe(0)
  })

  it('returns 0 for uniform single-byte buffer (all zeros)', () => {
    const buf = Buffer.alloc(1024) // all 0x00
    expect(calculateEntropy(buf)).toBe(0)
  })

  it('returns 0 for uniform single-value buffer (all 0xFF)', () => {
    const buf = Buffer.alloc(1024, 0xFF) // all 0xFF
    expect(calculateEntropy(buf)).toBe(0)
  })

  it('returns log2(256)=8 for perfectly random data (all bytes equally likely)', () => {
    // For true random data with uniform distribution, entropy = log2(256) = 8
    // Create an array with all 256 byte values appearing equally
    const arr = new Array(256 * 10).fill(0).map((_, i) => i % 256)
    const buf = Buffer.from(arr)
    const entropy = calculateEntropy(buf)
    // Should be close to 8.0 (within 0.1 of tolerance)
    expect(entropy).toBeGreaterThan(7.9)
    expect(entropy).toBeLessThanOrEqual(8.0)
  })

  it('returns ~1 for buffer with only 2 distinct values equally distributed', () => {
    // Evenly alternating 0x00 and 0xFF → each appears 50% of the time
    // Entropy = -0.5*log2(0.5) - 0.5*log2(0.5) = 1.0
    const arr = new Array(1000).fill(0).map((_, i) => i % 2 === 0 ? 0x00 : 0xFF)
    const entropy = calculateEntropy(Buffer.from(arr))
    expect(entropy).toBeCloseTo(1.0, 1)
  })

  it('returns higher entropy for more varied data', () => {
    const low = Buffer.alloc(100, 0x41) // all 'A'
    const med = Buffer.from('A'.repeat(50) + 'B'.repeat(50)) // 2 values
    const high = Buffer.from(new Array(100).fill(0).map((_, i) => i % 256)) // 256 values
    const lowE = calculateEntropy(low)
    const medE = calculateEntropy(med)
    const highE = calculateEntropy(high)
    expect(lowE).toBeLessThan(medE)
    expect(medE).toBeLessThan(highE)
  })

  it('handles single byte buffers', () => {
    expect(calculateEntropy(Buffer.from([0x00]))).toBe(0)
    expect(calculateEntropy(Buffer.from([0x42]))).toBe(0)
  })

  it('handles two-byte buffer with different values', () => {
    // Two values each appearing once → p = 0.5 each → entropy = 1.0
    const entropy = calculateEntropy(Buffer.from([0x00, 0xFF]))
    expect(entropy).toBeCloseTo(1.0, 1)
  })

  it('is idempotent', () => {
    const buf = Buffer.from('Hello, World! This is a test buffer with enough variety.')
    const e1 = calculateEntropy(buf)
    const e2 = calculateEntropy(buf)
    expect(e1).toBe(e2)
  })
})

// ═══════════════════════════════════════════════════════
// riskScoreToLevel
// ═══════════════════════════════════════════════════════

describe('riskScoreToLevel', () => {
  it('returns "high" for score > 80', () => {
    expect(riskScoreToLevel(81)).toBe('high')
    expect(riskScoreToLevel(100)).toBe('high')
    expect(riskScoreToLevel(999)).toBe('high')
  })

  it('returns "medium" for score 51-80', () => {
    expect(riskScoreToLevel(51)).toBe('medium')
    expect(riskScoreToLevel(65)).toBe('medium')
    expect(riskScoreToLevel(80)).toBe('medium')
  })

  it('returns "low" for score <= 50', () => {
    expect(riskScoreToLevel(0)).toBe('low')
    expect(riskScoreToLevel(25)).toBe('low')
    expect(riskScoreToLevel(50)).toBe('low')
  })

  it('handles negative scores as low', () => {
    expect(riskScoreToLevel(-1)).toBe('low')
    expect(riskScoreToLevel(-100)).toBe('low')
  })

  it('handles boundary values correctly', () => {
    // 80 → medium (not high)
    expect(riskScoreToLevel(80)).toBe('medium')
    // 81 → high
    expect(riskScoreToLevel(81)).toBe('high')
    // 50 → low (not medium)
    expect(riskScoreToLevel(50)).toBe('low')
    // 51 → medium
    expect(riskScoreToLevel(51)).toBe('medium')
  })

  it('handles fractional scores', () => {
    expect(riskScoreToLevel(50.5)).toBe('medium')
    expect(riskScoreToLevel(80.1)).toBe('high')
    expect(riskScoreToLevel(30.9)).toBe('low')
  })
})

// ═══════════════════════════════════════════════════════
// matchKnownCheat
// ═══════════════════════════════════════════════════════

describe('matchKnownCheat', () => {
  it('returns empty array for unknown name', () => {
    const matches = matchKnownCheat('legitimate-software.exe')
    expect(matches).toEqual([])
  })

  it('returns empty array for empty string', () => {
    expect(matchKnownCheat('')).toEqual([])
  })

  it('is case-insensitive', () => {
    // xenos.exe is in KNOWN_PROCESSES, all casing variants should match
    const lower = matchKnownCheat('xenos.exe')
    const upper = matchKnownCheat('XENOS.EXE')
    const mixed = matchKnownCheat('XeNoS.eXe')
    expect(lower).toEqual(upper)
    expect(lower).toEqual(mixed)
    expect(lower.length).toBeGreaterThan(0)
  })

  it('returns matches for known cheat process names', () => {
    const matches = matchKnownCheat('cheatengine.exe')
    expect(matches.length).toBeGreaterThan(0)
    expect(matches.some(m => m.startsWith('process:'))).toBe(true)
  })

  it('returns file type matches for known cheat file extensions', () => {
    const matches = matchKnownCheat('extremeinjector.dll')
    expect(matches.length).toBeGreaterThan(0)
    expect(matches.some(m => m.startsWith('file:'))).toBe(true)
  })

  it('returns multiple match types when name matches multiple categories', () => {
    // cheatengine is in KNOWN_PROCESSES + cheatengine.dll is in KNOWN_CHEAT_FILES
    const matches = matchKnownCheat('cheatengine.dll')
    expect(matches.length).toBeGreaterThanOrEqual(2)
    const types = matches.map(m => m.split(':')[0])
    expect(types).toContain('process')
    expect(types).toContain('file')
  })

  it('does not return false positives for benign system names', () => {
    const benignNames = [
      'notepad.exe',
      'chrome.exe',
      'explorer.exe',
      'svchost.exe',
      'winword.exe',
    ]
    for (const name of benignNames) {
      const matches = matchKnownCheat(name)
      expect(matches).toEqual([])
    }
  })

  it('is deterministic (same input always returns same output)', () => {
    const name = 'xenos-injector-v2.exe'
    const r1 = matchKnownCheat(name)
    const r2 = matchKnownCheat(name)
    expect(r1).toEqual(r2)
  })
})
