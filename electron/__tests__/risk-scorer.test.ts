/**
 * Predator — Risk Scorer Tests (E18)
 *
 * Tests for weighted ML-inspired risk scoring:
 * classifySignal, calculateRisk, SIGNAL_WEIGHTS, rescoreResults, scoreToLevel, decayScore
 */
import { describe, it, expect } from 'vitest'
import {
  classifySignal,
  calculateRisk,
  rescoreResults,
  scoreToLevel,
  decayScore,
  SIGNAL_WEIGHTS,
} from '../risk-scorer'
import type { ScanResult } from '../types'

// ═══════════════════════════════════════════════════
// SIGNAL_WEIGHTS
// ═══════════════════════════════════════════════════

describe('SIGNAL_WEIGHTS', () => {
  it('has at least 20 signal categories', () => {
    expect(Object.keys(SIGNAL_WEIGHTS).length).toBeGreaterThanOrEqual(20)
  })

  it('all weights are between 0 and 1', () => {
    for (const weight of Object.values(SIGNAL_WEIGHTS)) {
      expect(weight).toBeGreaterThan(0)
      expect(weight).toBeLessThanOrEqual(1.0)
    }
  })

  it('memory_pattern has the highest weight (1.0)', () => {
    expect(SIGNAL_WEIGHTS['memory_pattern']).toBe(1.0)
  })

  it('filename_keyword has a low weight (0.15)', () => {
    expect(SIGNAL_WEIGHTS['filename_keyword']).toBe(0.15)
  })

  it('has critical signal types present', () => {
    const keys = Object.keys(SIGNAL_WEIGHTS)
    expect(keys).toContain('memory_pattern')
    expect(keys).toContain('yara_match')
    expect(keys).toContain('tlsh_match')
  })
})

// ═══════════════════════════════════════════════════
// classifySignal
// ═══════════════════════════════════════════════════

describe('classifySignal', () => {
  it('classifies memory pattern signals', () => {
    expect(classifySignal('byte pattern in memory')).toBe('memory_pattern')
    expect(classifySignal('aimbot detected')).toBe('memory_pattern')
    expect(classifySignal('ESP overlay found')).toBe('memory_pattern')
  })

  it('classifies DMA/FPGA signals', () => {
    expect(classifySignal('DMA device detected')).toBe('dma_fpga')
    expect(classifySignal('xilinx fpga firmware')).toBe('dma_fpga')
    expect(classifySignal('pcie leech card')).toBe('dma_fpga')
  })

  it('classifies injection signals', () => {
    expect(classifySignal('thread inject detected')).toBe('injection_detected')
    expect(classifySignal('process handle opened')).toBe('injection_detected')
  })

  it('classifies YARA match signals', () => {
    expect(classifySignal('YARA rule matched')).toBe('yara_match')
  })

  it('classifies TLSH/fuzzy match signals', () => {
    expect(classifySignal('tlsh match found')).toBe('tlsh_match')
    expect(classifySignal('fuzzy-hash:matched')).toBe('tlsh_match')
  })

  it('classifies entropy signals', () => {
    expect(classifySignal('high entropy detected')).toBe('entropy_high')
  })

  it('classifies unsigned binary signals', () => {
    expect(classifySignal('unsigned executable')).toBe('unsigned_binary')
    expect(classifySignal('no digital signature')).toBe('unsigned_binary')
  })

  it('classifies network signals', () => {
    expect(classifySignal('C2 connection')).toBe('network_c2')
    expect(classifySignal('bulletproof hosting')).toBe('network_c2')
    expect(classifySignal('proxy setting')).toBe('network_proxy')
    expect(classifySignal('wireguard VPN detected')).toBe('network_vpn')
    expect(classifySignal('firewall rule found')).toBe('firewall_rule')
    expect(classifySignal('suspicious DNS cache')).toBe('dns_cache')
  })

  it('classifies debug port signals', () => {
    expect(classifySignal('CEF devtools port')).toBe('debug_port')
    expect(classifySignal('remote debug detected')).toBe('debug_port')
  })

  it('returns default for unmatched signals', () => {
    expect(classifySignal('completely unrelated text')).toBe('default')
    expect(classifySignal('')).toBe('default')
  })

  it('is case-insensitive', () => {
    const lower = classifySignal('memory pattern detected')
    const upper = classifySignal('MEMORY PATTERN DETECTED')
    expect(lower).toBe(upper)
    expect(lower).not.toBe('default')
  })
})

// ═══════════════════════════════════════════════════
// calculateRisk
// ═══════════════════════════════════════════════════

describe('calculateRisk', () => {
  const baseResult: ScanResult = {
    path: 'C:\\test\\suspicious.exe',
    fileName: 'suspicious.exe',
    type: 'file',
    risk: 'low',
    matches: [],
    size: 4096,
    modifiedAt: new Date().toISOString(),
  }

  it('returns clean for empty results', () => {
    const score = calculateRisk([])
    expect(score.level).toBe('clean')
    expect(score.overall).toBe(0)
    expect(score.totalEvidence).toBe(0)
  })

  it('returns clean for results with no matches', () => {
    const score = calculateRisk([{ ...baseResult, matches: [] }])
    expect(score.level).toBe('clean')
  })

  it('escalates risk for memory pattern matches', () => {
    const r: ScanResult = {
      ...baseResult,
      matches: ['byte pattern in memory', 'aimbot detected', 'overlay found'],
      risk: 'high',
    }
    const score = calculateRisk([r])
    expect(score.level).not.toBe('clean')
    expect(score.overall).toBeGreaterThan(0)
    expect(score.totalEvidence).toBe(3)
  })

  it('accumulates evidence from multiple signal types', () => {
    const results: ScanResult[] = [
      {
        ...baseResult,
        matches: ['byte pattern in memory', 'aimbot detected'],
        risk: 'high',
      },
      {
        ...baseResult,
        path: 'C:\\test\\injector.dll',
        fileName: 'injector.dll',
        matches: ['thread inject detected', 'process handle opened'],
        risk: 'high',
      },
      {
        ...baseResult,
        path: 'C:\\test\\unknown.sys',
        fileName: 'unknown.sys',
        matches: ['unsigned driver', 'DMA device detected'],
        risk: 'high',
      },
    ]
    const score = calculateRisk(results)
    // Multiple high-weight signals should produce high/critical
    expect(['high', 'critical']).toContain(score.level)
    expect(score.totalEvidence).toBeGreaterThanOrEqual(4)
  })

  it('applies escalation bonus', () => {
    const r: ScanResult = {
      ...baseResult,
      matches: ['byte pattern in memory'],
      risk: 'high',
    }
    const withoutBonus = calculateRisk([r], 0)
    const withBonus = calculateRisk([r], 25)
    expect(withBonus.overall).toBeGreaterThanOrEqual(withoutBonus.overall)
    expect(withBonus.escalated).toBe(true)
    expect(withoutBonus.escalated).toBe(false)
  })

  it('is deterministic', () => {
    const results: ScanResult[] = [{
      ...baseResult,
      matches: ['thread inject detected', 'YARA rule matched'],
    }]
    const r1 = calculateRisk(results)
    const r2 = calculateRisk(results)
    expect(r1.overall).toBe(r2.overall)
    expect(r1.level).toBe(r2.level)
  })

  it('uses adaptive threshold based on evidence count', () => {
    const fewResults: ScanResult[] = [{
      ...baseResult,
      matches: ['unsigned executable'],
    }]
    const manyResults: ScanResult[] = Array(30).fill(null).map((_, i) => ({
      ...baseResult,
      path: `C:\\test\\file${i}.exe`,
      fileName: `file${i}.exe`,
      matches: ['unsigned executable', 'thread inject detected'],
      risk: 'medium' as const,
    }))
    const fewScore = calculateRisk(fewResults)
    const manyScore = calculateRisk(manyResults)
    // More evidence → lower threshold → easier to classify as suspicious
    expect(manyScore.threshold).toBeLessThan(fewScore.threshold)
  })

  it('categories breakdown has correct structure', () => {
    const results: ScanResult[] = [{
      ...baseResult,
      matches: ['byte pattern in memory', 'YARA rule matched', 'unsigned executable'],
    }]
    const score = calculateRisk(results)
    expect(score.categories).toBeDefined()
    for (const [cat, data] of Object.entries(score.categories)) {
      expect(typeof data.score).toBe('number')
      expect(typeof data.count).toBe('number')
      expect(data.count).toBeGreaterThan(0)
    }
  })
})

// ═══════════════════════════════════════════════════
// rescoreResults
// ═══════════════════════════════════════════════════

describe('rescoreResults', () => {
  it('returns empty array for empty input', () => {
    expect(rescoreResults([])).toEqual([])
  })

  it('returns same array length', () => {
    const results: ScanResult[] = [
      {
        path: 'C:\\a.exe', fileName: 'a.exe', type: 'file',
        risk: 'low', matches: ['unsigned executable'],
        size: 1024, modifiedAt: new Date().toISOString(),
      },
      {
        path: 'C:\\b.dll', fileName: 'b.dll', type: 'file',
        risk: 'high', matches: ['byte pattern in memory', 'YARA rule matched'],
        size: 2048, modifiedAt: new Date().toISOString(),
      },
    ]
    const rescored = rescoreResults(results)
    expect(rescored).toHaveLength(2)
  })

  it('preserves high-risk results', () => {
    const r: ScanResult = {
      path: 'C:\\cheat.dll', fileName: 'cheat.dll', type: 'file',
      risk: 'high',
      matches: ['byte pattern in memory', 'YARA rule matched', 'thread inject detected'],
      size: 8192, modifiedAt: new Date().toISOString(),
    }
    const rescored = rescoreResults([r])
    expect(rescored[0].risk).not.toBe('low')
  })

  it('preserves low-risk clean results', () => {
    const r: ScanResult = {
      path: 'C:\\notepad.exe', fileName: 'notepad.exe', type: 'file',
      risk: 'low', matches: [],
      size: 256000, modifiedAt: new Date().toISOString(),
    }
    const rescored = rescoreResults([r])
    // No matches = no weight = risk stays 'low'
    expect(rescored[0].risk).toBe('low')
  })

  it('escalates medium to high when high-weight signals present', () => {
    const r: ScanResult = {
      path: 'C:\\svch0st.exe', fileName: 'svch0st.exe', type: 'file',
      risk: 'medium',
      matches: ['byte pattern in memory', 'DMA device detected'],
      size: 1024, modifiedAt: new Date().toISOString(),
    }
    const rescored = rescoreResults([r])
    // High-weight signals (memory_pattern=1.0, dma_fpga=0.95) → escalation
    expect(rescored[0].risk).toBe('high')
    expect(rescored[0].matches.some(m => m.includes('Escalated'))).toBe(true)
  })

  it('escalates low to medium when moderate-weight signals present', () => {
    const r: ScanResult = {
      path: 'C:\\suspicious.dll', fileName: 'suspicious.dll', type: 'file',
      risk: 'low',
      matches: ['YARA rule matched', 'tlsh match found', 'unsigned driver'],
      size: 4096, modifiedAt: new Date().toISOString(),
    }
    const rescored = rescoreResults([r])
    // yara_match=0.7 ≥ 0.6 → escalation
    expect(rescored[0].risk).toBe('medium')
    expect(rescored[0].matches.some(m => m.includes('Escalated'))).toBe(true)
  })
})

// ═══════════════════════════════════════════════════
// scoreToLevel
// ═══════════════════════════════════════════════════

describe('scoreToLevel', () => {
  it('returns critical for score >= 85', () => {
    expect(scoreToLevel(85)).toBe('critical')
    expect(scoreToLevel(100)).toBe('critical')
  })

  it('returns high for score 65-84', () => {
    expect(scoreToLevel(65)).toBe('high')
    expect(scoreToLevel(84)).toBe('high')
  })

  it('returns medium for score 35-64', () => {
    expect(scoreToLevel(35)).toBe('medium')
    expect(scoreToLevel(64)).toBe('medium')
  })

  it('returns low for score 15-34', () => {
    expect(scoreToLevel(15)).toBe('low')
    expect(scoreToLevel(34)).toBe('low')
  })

  it('returns clean for score < 15', () => {
    expect(scoreToLevel(0)).toBe('clean')
    expect(scoreToLevel(14)).toBe('clean')
  })

  it('handles edge case: score 100', () => {
    expect(scoreToLevel(100)).toBe('critical')
  })
})

// ═══════════════════════════════════════════════════
// decayScore
// ═══════════════════════════════════════════════════

describe('decayScore', () => {
  it('returns 0 for very old findings', () => {
    const veryOld = 365 * 24 * 60 * 60 * 1000 // 1 year
    expect(decayScore(100, veryOld)).toBe(0)
  })

  it('returns near-full score for recent findings', () => {
    const recent = 60 * 60 * 1000 // 1 hour
    const decayed = decayScore(100, recent)
    expect(decayed).toBeGreaterThanOrEqual(90)
  })

  it('returns approximately half after 7 days (half-life)', () => {
    const week = 7 * 24 * 60 * 60 * 1000
    const decayed = decayScore(100, week)
    expect(decayed).toBeGreaterThanOrEqual(40)
    expect(decayed).toBeLessThanOrEqual(60)
  })
})
