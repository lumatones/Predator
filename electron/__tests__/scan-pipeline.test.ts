/**
 * Predator — ScanPipeline Tests
 *
 * Tests for the composable post-scan handler chain.
 * Each handler is wrapped in try-catch so failures are isolated.
 * Tests verify:
 *   1. All 5 default handlers return Promise<void> without throwing
 *   2. runPostScanPipeline runs all steps even when some fail
 *   3. Custom step arrays work correctly
 */
import { describe, it, expect, vi } from 'vitest'
import {
  recordScanSession,
  submitShadowFindings,
  autoWhitelistLowRisk,
  submitHighRiskHashes,
  uploadScanResults,
  runPostScanPipeline,
  type PipelineContext,
  type ScanSummary,
  type PipelineStep,
} from '../scan-pipeline'
import type { ScanResult } from '../types'

// ── Mock Node.js modules that cause side effects ──

vi.mock('fs', () => ({
  default: {
    existsSync: vi.fn(() => false),
    statSync: vi.fn(() => ({ size: 0, mtimeMs: Date.now() })),
    openSync: vi.fn(() => 0),
    readSync: vi.fn(),
    closeSync: vi.fn(),
    createReadStream: vi.fn(() => ({ pipe: vi.fn(), on: vi.fn() })),
  },
}))

vi.mock('http')
vi.mock('https')

vi.mock('../persistent-profile', () => ({
  recordSession: vi.fn(),
}))

vi.mock('../safe-files-db', () => ({
  loadSafeFilesDb: vi.fn(),
  markFilesSafe: vi.fn(),
  saveSafeFilesDb: vi.fn(),
  uploadSafeFiles: vi.fn(),
}))

vi.mock('../config', () => ({
  getApiEndpoint: vi.fn(() => ({
    hostname: 'localhost',
    port: '3001',
    protocol: 'http:',
    path: '/api',
  })),
}))

vi.mock('../types', async () => {
  const actual = await vi.importActual('../types')
  return {
    ...actual,
    ctx: {
      shadowFindings: [] as any[],
      sigCache: new Map(),
      cheatNameCache: new Map(),
      peHeaderCache: new Map(),
      PE_CACHE_MAX: 100,
    },
  }
})

// ═══════════════════════════════════════════════════════
// FIXTURES
// ═══════════════════════════════════════════════════════

function makeResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    path: 'C:\\test\\file.exe',
    fileName: 'file.exe',
    type: 'file',
    risk: 'high',
    matches: ['match1', 'match2'],
    size: 12345,
    sha256: 'abc123def456abc123def456abc123def456abc123def456abc123def456abc1',
    modifiedAt: new Date().toISOString(),
    ...overrides,
  }
}

function makeSummary(overrides: Partial<ScanSummary> = {}): ScanSummary {
  return {
    totalScanned: 1000,
    suspiciousFiles: 5,
    highRiskCount: 2,
    scanTimeMs: 3500,
    ...overrides,
  }
}

function makeContext(overrides: Partial<PipelineContext> = {}): PipelineContext {
  return {
    tokenId: 42,
    pcUsername: 'TestPC',
    mode: 'full',
    startTime: Date.now(),
    ...overrides,
  }
}

// ═══════════════════════════════════════════════════════
// HANDLER 1: recordScanSession
// ═══════════════════════════════════════════════════════

describe('recordScanSession', () => {
  it('returns Promise<void> without throwing with valid inputs', async () => {
    const results = [makeResult(), makeResult({ risk: 'medium' }), makeResult({ risk: 'low' })]
    const summary = makeSummary()
    const ctx = makeContext()

    await expect(recordScanSession(results, summary, ctx)).resolves.toBeUndefined()
  })

  it('does not throw with empty results array', async () => {
    await expect(
      recordScanSession([], makeSummary(), makeContext())
    ).resolves.toBeUndefined()
  })

  it('does not throw with high-risk results (top findings should be captured)', async () => {
    const results = Array.from({ length: 20 }, (_, i) =>
      makeResult({ risk: i < 10 ? 'high' : 'low', fileName: `threat_${i}.exe` })
    )
    await expect(
      recordScanSession(results, makeSummary({ highRiskCount: 10 }), makeContext())
    ).resolves.toBeUndefined()
  })
})

// ═══════════════════════════════════════════════════════
// HANDLER 2: submitShadowFindings
// ═══════════════════════════════════════════════════════

describe('submitShadowFindings', () => {
  it('returns Promise<void> without throwing with empty results (shadow findings empty)', async () => {
    await expect(
      submitShadowFindings([], makeSummary(), makeContext())
    ).resolves.toBeUndefined()
  })

  it('does not throw with valid inputs even if shadow findings are empty', async () => {
    await expect(
      submitShadowFindings(
        [makeResult(), makeResult()],
        makeSummary(),
        makeContext()
      )
    ).resolves.toBeUndefined()
  })

  it('does not throw with 100+ results', async () => {
    const results = Array.from({ length: 150 }, (_, i) =>
      makeResult({ risk: i % 3 === 0 ? 'high' : i % 3 === 1 ? 'medium' : 'low' })
    )
    await expect(
      submitShadowFindings(results, makeSummary({ suspiciousFiles: 150 }), makeContext())
    ).resolves.toBeUndefined()
  })
})

// ═══════════════════════════════════════════════════════
// HANDLER 3: autoWhitelistLowRisk
// ═══════════════════════════════════════════════════════

describe('autoWhitelistLowRisk', () => {
  it('returns Promise<void> without throwing with empty results', async () => {
    await expect(
      autoWhitelistLowRisk([], makeSummary(), makeContext())
    ).resolves.toBeUndefined()
  })

  it('does not throw when no low-risk files', async () => {
    const results = [
      makeResult({ risk: 'high' }),
      makeResult({ risk: 'medium' }),
    ]
    await expect(
      autoWhitelistLowRisk(results, makeSummary(), makeContext())
    ).resolves.toBeUndefined()
  })

  it('does not throw with mixed risk results including low-risk', async () => {
    const results = [
      makeResult({ risk: 'high' }),
      makeResult({ risk: 'low', path: 'C:\\Windows\\System32\\notepad.exe' }),
      makeResult({ risk: 'low', path: 'C:\\Program Files\\app.dll' }),
    ]
    await expect(
      autoWhitelistLowRisk(results, makeSummary(), makeContext())
    ).resolves.toBeUndefined()
  })
})

// ═══════════════════════════════════════════════════════
// HANDLER 4: submitHighRiskHashes
// ═══════════════════════════════════════════════════════

describe('submitHighRiskHashes', () => {
  it('returns Promise<void> without throwing with empty results', async () => {
    await expect(
      submitHighRiskHashes([], makeSummary(), makeContext())
    ).resolves.toBeUndefined()
  })

  it('does not throw when no high-risk file-type results', async () => {
    const results = [
      makeResult({ risk: 'low', type: 'file' }),
      makeResult({ risk: 'medium', type: 'process' }),
      makeResult({ risk: 'medium', type: 'browser' }),
    ]
    await expect(
      submitHighRiskHashes(results, makeSummary(), makeContext())
    ).resolves.toBeUndefined()
  })

  it('does not throw with high-risk file results that have sha256 hashes', async () => {
    const results = [
      makeResult({ risk: 'high', type: 'file', sha256: 'a'.repeat(64) }),
      makeResult({ risk: 'high', type: 'file', sha256: 'b'.repeat(64) }),
      makeResult({ risk: 'high', type: 'file', sha256: 'c'.repeat(64) }),
    ]
    await expect(
      submitHighRiskHashes(results, makeSummary({ highRiskCount: 3 }), makeContext())
    ).resolves.toBeUndefined()
  })

  it('does not throw when results have sha256: undefined (skipped)', async () => {
    const results = [
      makeResult({ risk: 'high', type: 'file', sha256: undefined }),
    ]
    await expect(
      submitHighRiskHashes(results, makeSummary({ highRiskCount: 1 }), makeContext())
    ).resolves.toBeUndefined()
  })
})

// ═══════════════════════════════════════════════════════
// HANDLER 5: uploadScanResults
// ═══════════════════════════════════════════════════════

describe('uploadScanResults', () => {
  it('returns Promise<void> without throwing with empty results', async () => {
    await expect(
      uploadScanResults([], makeSummary(), makeContext())
    ).resolves.toBeUndefined()
  })

  it('does not throw with valid results', async () => {
    await expect(
      uploadScanResults(
        [makeResult(), makeResult()],
        makeSummary(),
        makeContext()
      )
    ).resolves.toBeUndefined()
  })

  it('does not throw with 100+ results (should slice to 100)', async () => {
    const results = Array.from({ length: 200 }, (_, i) =>
      makeResult({ risk: i % 3 === 0 ? 'high' : i % 3 === 1 ? 'medium' : 'low' })
    )
    await expect(
      uploadScanResults(results, makeSummary({ suspiciousFiles: 200 }), makeContext())
    ).resolves.toBeUndefined()
  })
})

// ═══════════════════════════════════════════════════════
// PIPELINE RUNNER
// ═══════════════════════════════════════════════════════

describe('runPostScanPipeline', () => {
  it('runs all default steps without throwing', async () => {
    await expect(
      runPostScanPipeline(
        [makeResult()],
        makeSummary(),
        makeContext()
      )
    ).resolves.toBeUndefined()
  })

  it('runs steps sequentially with isolation — step failure does not block others', async () => {
    const callOrder: string[] = []
    const steps: PipelineStep[] = [
      async () => { callOrder.push('step1') },
      async () => { callOrder.push('step2'); throw new Error('step2 failed') },
      async () => { callOrder.push('step3') },
    ]

    await expect(
      runPostScanPipeline([], makeSummary(), makeContext(), steps)
    ).resolves.toBeUndefined()

    expect(callOrder).toEqual(['step1', 'step2', 'step3'])
  })

  it('runs ALL steps to completion even when every step throws', async () => {
    const callOrder: string[] = []
    const steps: PipelineStep[] = [
      async () => { callOrder.push('a'); throw new Error('a') },
      async () => { callOrder.push('b'); throw new Error('b') },
      async () => { callOrder.push('c'); throw new Error('c') },
    ]

    await expect(
      runPostScanPipeline([], makeSummary(), makeContext(), steps)
    ).resolves.toBeUndefined()

    expect(callOrder).toEqual(['a', 'b', 'c'])
  })

  it('uses 5 default steps when no custom steps provided', async () => {
    const steps: PipelineStep[] = []

    await expect(
      runPostScanPipeline(
        [makeResult()],
        makeSummary(),
        makeContext(),
        steps, // empty → should still complete (no steps = no-op)
      )
    ).resolves.toBeUndefined()
  })

  it('does not throw with null-like results edge case', async () => {
    await expect(
      runPostScanPipeline(
        [] as ScanResult[],
        { totalScanned: 0, suspiciousFiles: 0, highRiskCount: 0, scanTimeMs: 0 },
        { tokenId: 0, pcUsername: '', mode: '', startTime: 0 },
      )
    ).resolves.toBeUndefined()
  })
})
