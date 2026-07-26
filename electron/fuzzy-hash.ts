/**
 * Predator — Fuzzy Hashing (TLSH)
 *
 * Computes TLSH (Trend Micro Locality Sensitive Hash) for executable files
 * to detect polymorphic cheat variants that have different SHA256 hashes
 * but nearly identical binary structure.
 *
 * Uses the 'tlsh' npm package (pure JS, no node-gyp).
 * Minimum input: 512 bytes. Files smaller than 512 bytes are skipped.
 */

import { createHash } from 'crypto'
import fs from 'fs'
import tlshLib from 'tlsh'

// ── Types ──

export interface FuzzyHashResult {
  sha256: string
  tlsh: string
  fileSize: number
}

export interface FuzzyMatchResult {
  matched: boolean
  distance: number
  queryHash: string
  matchedHash: string
}

// ── Constants ──

/** Minimum file size for TLSH computation (512 bytes per spec) */
const TLSH_MIN_SIZE = 512

/** Maximum distance to consider two hashes as the same file variant */
const DEFAULT_DISTANCE_THRESHOLD = 30

// ── In-memory known TLSH database ──

let _knownTlshHashes: Set<string> = new Set()

export function getKnownTlshHashes(): string[] {
  return Array.from(_knownTlshHashes)
}

export function setKnownTlshHashes(hashes: string[]): void {
  _knownTlshHashes = new Set(hashes.filter(h => h && h.length > 10))
}

export function mergeTlshHashes(hashes: string[]): void {
  for (const h of hashes) {
    if (h && h.length > 10) _knownTlshHashes.add(h)
  }
}

/** Clear the TLSH database */
export function clearTlshCache(): void {
  _knownTlshHashes = new Set()
}

// ── Core: compute TLSH ──

/**
 * Compute TLSH hash for a file.
 * Returns null if file is too small, doesn't exist, or has insufficient complexity.
 */
export function computeFuzzyHash(filePath: string): FuzzyHashResult | null {
  try {
    const stat = fs.statSync(filePath)
    if (!stat.isFile() || stat.size < TLSH_MIN_SIZE) return null

    const buffer = fs.readFileSync(filePath)
    const sha256 = createHash('sha256').update(buffer).digest('hex')

    let tlsh: string
    try {
      tlsh = tlshLib.hash(buffer)
    } catch (_e) {
      // TLSH InsufficientComplexityError — file doesn't have enough randomness
      return null
    }

    return { sha256, tlsh, fileSize: stat.size }
  } catch {
    return null
  }
}

/**
 * Compute TLSH hash from an existing Buffer.
 * For memory dumps / already-read files.
 */
export function computeFuzzyHashFromBuffer(buffer: Buffer): string | null {
  if (buffer.length < TLSH_MIN_SIZE) return null
  try {
    return tlshLib.hash(buffer)
  } catch {
    return null
  }
}

// ── Core: compare ──

/**
 * Compare a TLSH hash against the known database.
 * Returns the best match (lowest distance) under threshold, or null.
 */
export function fuzzyMatch(
  queryHash: string,
  database: string[],
  threshold: number = DEFAULT_DISTANCE_THRESHOLD,
): FuzzyMatchResult | null {
  if (!queryHash || database.length === 0) return null

  let bestDistance = Infinity
  let bestMatch = ''

  for (const known of database) {
    try {
      const diff = tlshLib.diff(known, queryHash)
      if (diff < bestDistance && diff <= threshold) {
        bestDistance = diff
        bestMatch = known
      }
    } catch {
      // Invalid TLSH string — skip
      continue
    }
  }

  if (bestDistance === Infinity) return null

  return {
    matched: true,
    distance: bestDistance,
    queryHash,
    matchedHash: bestMatch,
  }
}

/**
 * Check a file against the fuzzy hash database.
 * Convenience wrapper: compute TLSH → fuzzy match.
 */
export function fuzzyMatchFile(
  filePath: string,
  threshold: number = DEFAULT_DISTANCE_THRESHOLD,
): FuzzyMatchResult | null {
  const result = computeFuzzyHash(filePath)
  if (!result) return null

  const database = getKnownTlshHashes()
  return fuzzyMatch(result.tlsh, database, threshold)
}

// ── Utility ──

/**
 * Compute distance between two TLSH hashes directly (without DB lookup).
 * Returns -1 if either hash is invalid.
 */
export function tlshDistance(hash1: string, hash2: string): number {
  try {
    return tlshLib.diff(hash1, hash2)
  } catch {
    return -1
  }
}

/** Group TLSH hashes by distance threshold (for clustering Auto-YARA) */
export function clusterByTlsh(
  hashes: string[],
  threshold: number = DEFAULT_DISTANCE_THRESHOLD,
): string[][] {
  const clusters: string[][] = []
  const used = new Set<number>()

  for (let i = 0; i < hashes.length; i++) {
    if (used.has(i)) continue
    const cluster: string[] = [hashes[i]]
    used.add(i)

    for (let j = i + 1; j < hashes.length; j++) {
      if (used.has(j)) continue
      try {
        const dist = tlshLib.diff(hashes[i], hashes[j])
        if (dist <= threshold) {
          cluster.push(hashes[j])
          used.add(j)
        }
      } catch {
        continue
      }
    }

    if (cluster.length >= 2) clusters.push(cluster)
  }

  return clusters
}
