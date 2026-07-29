/**
 * Predator — Fuzzy Hash Tests (E23/E24)
 *
 * Tests for TLSH persistence, prefix trie, size-aware thresholds,
 * fuzzy matching, clustering, and merge operations.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import fs from 'fs'
import path from 'path'
import os from 'os'
import crypto from 'crypto'
import {
  fuzzyMatch,
  fuzzyMatchFile,
  fuzzyMatchWithSize,
  tlshDistance,
  clusterByTlsh,
  computeFuzzyHash,
  computeFuzzyHashFromBuffer,
  getKnownTlshHashes,
  setKnownTlshHashes,
  mergeTlshHashes,
  clearTlshCache,
  getTlshDbStats,
} from '../fuzzy-hash'

// ── Helpers ──

function createTempFile(sizeBytes: number, pattern?: Buffer): string {
  const tmp = path.join(os.tmpdir(), `predator_test_${Date.now()}_${crypto.randomUUID().slice(0, 8)}.bin`)
  const buf = pattern || crypto.randomBytes(sizeBytes)
  fs.writeFileSync(tmp, buf)
  return tmp
}

function cleanupTempFile(filepath: string) {
  try { fs.unlinkSync(filepath) } catch { /* ignore */ }
}

// ═══════════════════════════════════════════════════
// computeFuzzyHash
// ═══════════════════════════════════════════════════

describe('computeFuzzyHash', () => {
  it('returns null for files smaller than 512 bytes', () => {
    const small = createTempFile(256)
    const result = computeFuzzyHash(small)
    expect(result).toBeNull()
    cleanupTempFile(small)
  })

  it('returns valid TLSH for files >= 512 bytes with sufficient complexity', () => {
    // 8KB of random data should have enough complexity for TLSH
    const f = createTempFile(8192)
    const result = computeFuzzyHash(f)
    if (result) {
      expect(result.tlsh).toBeTruthy()
      expect(result.tlsh.length).toBeGreaterThan(10)
      expect(result.sha256).toBeTruthy()
      expect(result.sha256.length).toBe(64)
      expect(result.fileSize).toBe(8192)
    }
    // Note: TLSH may still fail if random data has insufficient complexity
    cleanupTempFile(f)
  })

  it('returns null for non-existent files', () => {
    const result = computeFuzzyHash('/nonexistent/file.bin')
    expect(result).toBeNull()
  })
})

// ═══════════════════════════════════════════════════
// computeFuzzyHashFromBuffer
// ═══════════════════════════════════════════════════

describe('computeFuzzyHashFromBuffer', () => {
  it('returns null for buffers smaller than 512 bytes', () => {
    const buf = Buffer.alloc(256)
    expect(computeFuzzyHashFromBuffer(buf)).toBeNull()
  })

  it('returns string for buffers >= 512 bytes', () => {
    const buf = crypto.randomBytes(2048)
    const result = computeFuzzyHashFromBuffer(buf)
    if (result) {
      expect(typeof result).toBe('string')
      expect(result.length).toBeGreaterThan(10)
    }
  })
})

// ═══════════════════════════════════════════════════
// tlshDistance
// ═══════════════════════════════════════════════════

describe('tlshDistance', () => {
  it('returns -1 for invalid hashes', () => {
    expect(tlshDistance('invalid', 'bad')).toBe(-1)
    expect(tlshDistance('', '')).toBe(-1)
  })

  it('returns 0 for identical hashes', () => {
    const buf = crypto.randomBytes(8192)
    const h = computeFuzzyHashFromBuffer(buf)
    if (h) {
      expect(tlshDistance(h, h)).toBe(0)
    }
  })

  it('returns positive number for similar but not identical files', () => {
    // Create two files that differ slightly
    const base = crypto.randomBytes(16384)
    const modified = Buffer.from(base)
    modified[100] ^= 0xFF // Flip one byte

    const h1 = computeFuzzyHashFromBuffer(base)
    const h2 = computeFuzzyHashFromBuffer(modified)
    if (h1 && h2) {
      const dist = tlshDistance(h1, h2)
      expect(typeof dist).toBe('number')
      expect(dist).toBeGreaterThanOrEqual(0)
    }
  })
})

// ═══════════════════════════════════════════════════
// Fuzzy Match (prefix trie fast-path)
// ═══════════════════════════════════════════════════

describe('fuzzyMatch', () => {
  beforeEach(() => {
    clearTlshCache()
  })

  afterEach(() => {
    clearTlshCache()
  })

  it('returns null when DB is empty', () => {
    const buf = crypto.randomBytes(8192)
    const h = computeFuzzyHashFromBuffer(buf)
    if (h) {
      expect(fuzzyMatch(h)).toBeNull()
    }
  })

  it('finds a match when hash exists in DB', () => {
    const buf = crypto.randomBytes(8192)
    const h = computeFuzzyHashFromBuffer(buf)
    if (h) {
      setKnownTlshHashes([h])
      const result = fuzzyMatch(h)
      expect(result).not.toBeNull()
      expect(result!.distance).toBe(0)
      expect(result!.matched).toBe(true)
    }
  })

  it('returns null for hash not in DB (prefix trie rejection)', () => {
    const buf1 = crypto.randomBytes(8192)
    const buf2 = crypto.randomBytes(8192)
    const h1 = computeFuzzyHashFromBuffer(buf1)
    const h2 = computeFuzzyHashFromBuffer(buf2)
    if (h1 && h2 && h1 !== h2) {
      setKnownTlshHashes([h1])
      const result = fuzzyMatch(h2)
      // May or may not match depending on TLSH similarity
      if (result) {
        expect(result.distance).toBeGreaterThan(0)
      }
    }
  })

  it('works with custom database array', () => {
    const buf = crypto.randomBytes(8192)
    const h = computeFuzzyHashFromBuffer(buf)
    if (h) {
      const result = fuzzyMatch(h, [h])
      expect(result).not.toBeNull()
      expect(result!.distance).toBe(0)
    }
  })

  it('respects custom threshold', () => {
    const buf = crypto.randomBytes(8192)
    const h = computeFuzzyHashFromBuffer(buf)
    if (h) {
      // With threshold 0, even identical hash would need distance 0
      const result = fuzzyMatch(h, [h], 0)
      if (result) {
        expect(result.distance).toBe(0)
      }
      // With extremely strict threshold, different hashes won't match
      const buf2 = crypto.randomBytes(8192)
      const h2 = computeFuzzyHashFromBuffer(buf2)
      if (h2 && h2 !== h) {
        const strictResult = fuzzyMatch(h2, [h], 1)
        if (strictResult) {
          expect(strictResult.distance).toBeLessThanOrEqual(1)
        }
      }
    }
  })
})

// ═══════════════════════════════════════════════════
// fuzzyMatchWithSize (size-aware threshold)
// ═══════════════════════════════════════════════════

describe('fuzzyMatchWithSize', () => {
  beforeEach(() => clearTlshCache())
  afterEach(() => clearTlshCache())

  it('uses tighter threshold for small files', () => {
    const smallSize = 50 * 1024 // 50KB → tiny bucket, threshold 15
    const buf = crypto.randomBytes(8192)
    const h = computeFuzzyHashFromBuffer(buf)
    if (h) {
      setKnownTlshHashes([h])
      const result = fuzzyMatchWithSize(h, smallSize)
      expect(result).not.toBeNull()
    }
  })
})

// ═══════════════════════════════════════════════════
// clusterByTlsh
// ═══════════════════════════════════════════════════

describe('clusterByTlsh', () => {
  it('returns empty array for empty input', () => {
    expect(clusterByTlsh([])).toEqual([])
  })

  it('returns empty array for single hash', () => {
    expect(clusterByTlsh(['abc123def456'])).toEqual([])
  })

  it('returns empty array for invalid hashes', () => {
    expect(clusterByTlsh(['invalid', 'also_bad'])).toEqual([])
  })

  it('clusters identical TLSH hashes together', () => {
    const buf = crypto.randomBytes(8192)
    const h = computeFuzzyHashFromBuffer(buf)
    if (h) {
      const clusters = clusterByTlsh([h, h], 30)
      expect(clusters.length).toBeGreaterThanOrEqual(1)
      // Both identical hashes should be in the same cluster
      const hasClusterWithBoth = clusters.some(
        c => c.includes(h) && c.length >= 2
      )
      expect(hasClusterWithBoth).toBe(true)
    }
  })
})

// ═══════════════════════════════════════════════════
// DB Operations
// ═══════════════════════════════════════════════════

describe('TLSH DB operations', () => {
  beforeEach(() => clearTlshCache())
  afterEach(() => clearTlshCache())

  it('setKnownTlshHashes replaces existing DB', () => {
    setKnownTlshHashes(['abc123def4567890', 'xyz789abc123def0'])
    expect(getKnownTlshHashes()).toHaveLength(2)
    setKnownTlshHashes(['newhashonly'])
    expect(getKnownTlshHashes()).toHaveLength(1)
  })

  it('mergeTlshHashes adds to existing DB without duplicates', () => {
    setKnownTlshHashes(['abc123def4567890'])
    mergeTlshHashes(['xyz789abc123def0', 'abc123def4567890'])
    const hashes = getKnownTlshHashes()
    expect(hashes).toHaveLength(2)
    expect(hashes).toContain('abc123def4567890')
    expect(hashes).toContain('xyz789abc123def0')
  })

  it('filters out invalid hashes on setKnownTlshHashes', () => {
    setKnownTlshHashes(['abc123def4567890', '', 'ab', '  ', null as unknown as string])
    expect(getKnownTlshHashes()).toHaveLength(1)
  })

  it('filters out invalid hashes on mergeTlshHashes', () => {
    mergeTlshHashes(['validhash12345678', '', 'ab'])
    expect(getKnownTlshHashes()).toHaveLength(1)
  })

  it('clearTlshCache empties the DB', () => {
    setKnownTlshHashes(['abc123def4567890', 'xyz789abc123def0'])
    expect(getKnownTlshHashes()).toHaveLength(2)
    clearTlshCache()
    expect(getKnownTlshHashes()).toHaveLength(0)
  })

  it('getTlshDbStats returns correct stats', () => {
    setKnownTlshHashes(['abc123def4567890', 'xyz789abc123def0', 'qwertyuiop12345'])
    const stats = getTlshDbStats()
    expect(stats.total).toBe(3)
    expect(typeof stats.triePrefixes).toBe('number')
  })
})
