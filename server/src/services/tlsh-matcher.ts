/**
 * Predator — Server-side TLSH Fuzzy Hash Matcher
 *
 * Computes TLSH distance between incoming findings and confirmed cheat hashes.
 * Uses in-memory cache with TTL to avoid hammering the DB.
 *
 * TLSH (Trend Micro Locality Sensitive Hash) catches polymorphic cheat variants
 * that have different SHA256 but nearly identical binary structure.
 *
 * Thresholds (mirroring electron/fuzzy-hash.ts):
 *   - tiny   (<100KB):  distance <= 15
 *   - small  (100KB-1MB):  distance <= 22
 *   - medium (1MB-10MB):   distance <= 30
 *   - large  (>10MB):   distance <= 35
 */

import tlshLib from 'tlsh'
import { query } from '../config/database'

// ═══════════════════════════════════════════════════
// CACHE
// ═══════════════════════════════════════════════════

interface TlshCacheEntry {
  hashes: Array<{ tlsh: string; sha256: string; fileSize: number }>
  loadedAt: number
}

let _cache: TlshCacheEntry | null = null
const CACHE_TTL_MS = 5 * 60 * 1000 // 5 minutes

// ── Size-based thresholds (mirror electron/fuzzy-hash.ts) ──

function getThreshold(fileSize: number | undefined): number {
  if (!fileSize || fileSize <= 0) return 30 // default
  if (fileSize < 100 * 1024) return 15       // tiny
  if (fileSize < 1024 * 1024) return 22       // small
  if (fileSize < 10 * 1024 * 1024) return 30  // medium
  return 35                                    // large
}

// ═══════════════════════════════════════════════════
// PUBLIC API
// ═══════════════════════════════════════════════════

/**
 * Load confirmed TLSH hashes from DB into memory cache.
 * Cache lives for 5 minutes, then refreshes on next query.
 */
async function loadCachedHashes(): Promise<Array<{ tlsh: string; sha256: string; fileSize: number }>> {
  const now = Date.now()
  if (_cache && (now - _cache.loadedAt) < CACHE_TTL_MS) {
    return _cache.hashes
  }

  try {
    const rows = await query<{ tlsh: string; sha256: string; file_size: number }[]>(
      'SELECT tlsh, sha256, file_size FROM suspicious_hashes WHERE status = ? AND tlsh IS NOT NULL AND tlsh != ?',
      ['confirmed', '']
    )

    const hashes = rows
      .filter(r => r.tlsh && r.tlsh.length > 10)
      .map(r => ({ tlsh: r.tlsh, sha256: r.sha256, fileSize: r.file_size }))

    _cache = { hashes, loadedAt: now }
    console.log(`  🧬 TLSH cache loaded: ${hashes.length} confirmed hashes from DB`)
    return hashes
  } catch (err) {
    console.error('[tlsh-matcher] Failed to load cache:', err)
    return _cache?.hashes ?? []
  }
}

/**
 * Invalidate the cache so the next match forces a DB reload.
 */
export function invalidateTlshCache(): void {
  _cache = null
}

/**
 * Match a TLSH hash against all confirmed hashes in the DB.
 * Returns the best match if found within the size-appropriate threshold.
 *
 * @param queryTlsh — TLSH hash to check
 * @param fileSize — file size for threshold selection (optional)
 * @returns Best match result or null
 */
export async function matchTlsh(
  queryTlsh: string,
  fileSize?: number,
): Promise<{
  matched: boolean
  distance: number
  matchedSha256: string
  threshold: number
} | null> {
  if (!queryTlsh || queryTlsh.length < 10) return null

  const dbHashes = await loadCachedHashes()
  if (dbHashes.length === 0) return null

  const threshold = getThreshold(fileSize)
  let bestDistance = Infinity
  let bestMatch = ''

  for (const entry of dbHashes) {
    try {
      const dist = tlshLib.diff(entry.tlsh, queryTlsh)
      if (dist < bestDistance && dist <= threshold) {
        bestDistance = dist
        bestMatch = entry.sha256
        if (dist === 0) break // perfect match
      }
    } catch {
      continue // skip invalid TLSH pairs
    }
  }

  if (bestDistance === Infinity) return null

  return {
    matched: true,
    distance: bestDistance,
    matchedSha256: bestMatch,
    threshold,
  }
}

/**
 * Get cache stats for diagnostics.
 */
export function getTlshCacheStats(): { loaded: boolean; count: number; ageMs: number | null } {
  return {
    loaded: _cache !== null,
    count: _cache?.hashes.length ?? 0,
    ageMs: _cache ? Date.now() - _cache.loadedAt : null,
  }
}
