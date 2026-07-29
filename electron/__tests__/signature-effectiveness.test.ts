/**
 * Predator — Signature Effectiveness Tests (E26)
 *
 * Tests for hit counters, top-N keywords/patterns, pruning,
 * and effectiveness reporting.
 */
import { describe, it, expect, beforeEach } from 'vitest'
import {
  recordKeywordHit,
  recordPatternHit,
  getTopKeywords,
  getTopPatterns,
  getZeroHitKeywords,
  getZeroHitPatterns,
  pruneColdSignatures,
  resetHitCounters,
  setHitCountersEnabled,
  getEffectivenessReport,
  matchKeywords,
  matchPatterns,
} from '../signature-registry'

// ═══════════════════════════════════════════════════
// Hit Counters
// ═══════════════════════════════════════════════════

describe('Hit counters', () => {
  beforeEach(() => {
    resetHitCounters()
    setHitCountersEnabled(true)
  })

  it('recordKeywordHit tracks keyword hits', () => {
    recordKeywordHit('cheat')
    recordKeywordHit('cheat')
    recordKeywordHit('inject')
    const top = getTopKeywords(5)
    expect(top.length).toBeGreaterThanOrEqual(2)
    const cheat = top.find(k => k.keyword === 'cheat')
    expect(cheat).toBeDefined()
    expect(cheat!.hits).toBe(2)
  })

  it('recordPatternHit tracks pattern hits', () => {
    recordPatternHit('[Nn]ightfall')
    recordPatternHit('[Nn]ightfall')
    recordPatternHit('[Nn]ightfall')
    recordPatternHit('[Dd][Mm][Aa]')
    const top = getTopPatterns(5)
    const nightfall = top.find(p => p.pattern === '[Nn]ightfall')
    expect(nightfall).toBeDefined()
    expect(nightfall!.hits).toBe(3)
  })

  it('getTopKeywords respects count limit', () => {
    recordKeywordHit('cheat')
    recordKeywordHit('inject')
    recordKeywordHit('bypass')
    recordKeywordHit('hack')
    recordKeywordHit('dma')
    const top = getTopKeywords(3)
    expect(top.length).toBeLessThanOrEqual(3)
  })

  it('getTopPatterns respects count limit', () => {
    recordPatternHit('a')
    recordPatternHit('b')
    recordPatternHit('c')
    recordPatternHit('d')
    const top = getTopPatterns(2)
    expect(top.length).toBeLessThanOrEqual(2)
  })

  it('keyword hits are case-insensitive', () => {
    recordKeywordHit('CHEAT')
    recordKeywordHit('cheat')
    recordKeywordHit('Cheat')
    const top = getTopKeywords(5)
    const cheat = top.find(k => k.keyword.toLowerCase() === 'cheat')
    expect(cheat).toBeDefined()
    expect(cheat!.hits).toBe(3)
  })
})

// ═══════════════════════════════════════════════════
// Effectiveness Report (BEFORE any destructive tests)
// ═══════════════════════════════════════════════════

describe('getEffectivenessReport', () => {
  beforeEach(() => {
    resetHitCounters()
    setHitCountersEnabled(true)
  })

  it('returns a valid report structure', () => {
    const report = getEffectivenessReport()
    expect(report).toBeDefined()
    expect(typeof report.totalKeywords).toBe('number')
    expect(report.totalKeywords).toBeGreaterThan(0)
    expect(typeof report.totalPatterns).toBe('number')
    expect(report.totalPatterns).toBeGreaterThan(0)
    expect(typeof report.activeKeywords).toBe('number')
    expect(typeof report.activePatterns).toBe('number')
    expect(typeof report.zeroHitKeywords).toBe('number')
    expect(typeof report.zeroHitPatterns).toBe('number')
    expect(Array.isArray(report.topKeywords)).toBe(true)
    expect(Array.isArray(report.topPatterns)).toBe(true)
  })

  it('report includes hit-tracked data after matching', () => {
    matchKeywords('cheat engine injector bypass detected')
    matchPatterns('Nightfall DMA FPGA')
    const report = getEffectivenessReport()
    expect(report.topKeywords.length).toBeGreaterThanOrEqual(1)
    expect(report.topPatterns.length).toBeGreaterThanOrEqual(1)
  })

  it('topKeywords contain valid entries', () => {
    recordKeywordHit('cheat')
    recordKeywordHit('inject')
    const report = getEffectivenessReport()
    for (const kw of report.topKeywords) {
      expect(typeof kw.keyword).toBe('string')
      expect(typeof kw.hits).toBe('number')
      expect(kw.hits).toBeGreaterThan(0)
    }
  })

  it('topPatterns contain valid entries', () => {
    recordPatternHit('[Nn]ightfall')
    const report = getEffectivenessReport()
    for (const p of report.topPatterns) {
      expect(typeof p.pattern).toBe('string')
      expect(typeof p.hits).toBe('number')
      expect(p.hits).toBeGreaterThan(0)
    }
  })
})

// ═══════════════════════════════════════════════════
// Zero-Hit Detection
// ═══════════════════════════════════════════════════

describe('Zero-hit detection', () => {
  beforeEach(() => {
    resetHitCounters()
    setHitCountersEnabled(true)
  })

  it('getZeroHitKeywords returns non-empty list when no hits recorded', () => {
    const zero = getZeroHitKeywords()
    expect(zero.length).toBeGreaterThan(0)
  })

  it('getZeroHitPatterns returns non-empty list when no hits recorded', () => {
    const zero = getZeroHitPatterns()
    expect(zero.length).toBeGreaterThan(0)
  })

  it('hit keywords are excluded from zero-hit list', () => {
    recordKeywordHit('cheat')
    recordKeywordHit('inject')
    const zero = getZeroHitKeywords()
    expect(zero).not.toContain('cheat')
    expect(zero).not.toContain('inject')
  })
})

// ═══════════════════════════════════════════════════
// Pruning (LAST — records hits first to avoid destroying all keywords)
// ═══════════════════════════════════════════════════

describe('pruneColdSignatures', () => {
  beforeEach(() => {
    resetHitCounters()
    setHitCountersEnabled(true)
  })

  it('returns valid numbers and does not throw', () => {
    // Record some hits so pruning doesn't destroy everything
    recordKeywordHit('cheat')
    recordKeywordHit('inject')
    recordKeywordHit('hack')
    recordPatternHit('[Nn]ightfall')
    recordPatternHit('[Dd][Mm][Aa]')

    const result = pruneColdSignatures(30) // 30 days
    expect(typeof result.keywordsPruned).toBe('number')
    expect(result.keywordsPruned).toBeGreaterThanOrEqual(0)
    expect(typeof result.patternsPruned).toBe('number')
    expect(result.patternsPruned).toBeGreaterThanOrEqual(0)
  })
})

// ═══════════════════════════════════════════════════
// Hit Counter Control
// ═══════════════════════════════════════════════════

describe('Hit counter control', () => {
  beforeEach(() => {
    resetHitCounters()
    setHitCountersEnabled(true)
  })

  it('setHitCountersEnabled(false) disables counting', () => {
    setHitCountersEnabled(false)
    recordKeywordHit('cheat')
    const top = getTopKeywords(5)
    expect(top.length).toBe(0)
  })

  it('resetHitCounters clears all counters', () => {
    recordKeywordHit('cheat')
    recordPatternHit('[Nn]ightfall')
    expect(getTopKeywords(5).length).toBeGreaterThan(0)
    expect(getTopPatterns(5).length).toBeGreaterThan(0)
    resetHitCounters()
    expect(getTopKeywords(5).length).toBe(0)
    expect(getTopPatterns(5).length).toBe(0)
  })
})
