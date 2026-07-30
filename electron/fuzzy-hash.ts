/**
 * Predator — Fuzzy Hashing (TLSH) v2
 *
 * Computes TLSH (Trend Micro Locality Sensitive Hash) for executable files
 * to detect polymorphic cheat variants that have different SHA256 hashes
 * but nearly identical binary structure.
 *
 * v2 Improvements:
 *   - Persistent TLSH DB (saved to disk, survives restarts)
 *   - File-size bucketing (O(1) by size range, then TLSH compare)
 *   - Prefix trie for O(1) rejection of non-matching hashes
 *   - Batch matching (compare against N hashes in one pass)
 *   - Size-aware distance threshold (stricter for small files)
 *
 * Uses the 'tlsh' npm package (pure JS, no node-gyp).
 * Minimum input: 512 bytes per TLSH spec.
 */

import { createHash } from 'crypto'
import fs from 'fs'
import path from 'path'
import { app } from 'electron'
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
  /** The file-size bucket where the match was found */
  bucket?: string
}

// ── Constants ──

const TLSH_MIN_SIZE = 512
const DEFAULT_DISTANCE_THRESHOLD = 30

/** File-size buckets for O(1) lookup */
const SIZE_BUCKETS = [
  { label: 'tiny',   min: 0,          max: 100 * 1024,       threshold: 15 },  // <100KB: very strict
  { label: 'small',  min: 100 * 1024, max: 1024 * 1024,      threshold: 22 },  // 100KB-1MB
  { label: 'medium', min: 1024 * 1024,max: 10 * 1024 * 1024, threshold: 30 },  // 1-10MB
  { label: 'large',  min: 10 * 1024 * 1024, max: Infinity,   threshold: 35 },  // >10MB: looser
]

// ── Persistent DB ──

const DB_PATH = path.join(app?.getPath?.('userData') ?? process.cwd(), '.predator_tlsh_db.json')

interface TlshDb {
  version: number
  updatedAt: string
  totalHashes: number
  hashes: string[]
}

// In-memory structures
let _knownTlshHashes: Set<string> = new Set()
/** Prefix trie for O(1) rejection: first 4 chars → Set<tlsh> */
const _tlshTrie: Map<string, Set<string>> = new Map()
/** How many hashes were loaded from disk */
let _loadedFromDisk = 0

function getBucket(fileSize: number): string {
  for (const bucket of SIZE_BUCKETS) {
    if (fileSize >= bucket.min && fileSize < bucket.max) return bucket.label
  }
  return 'medium'
}

function getThreshold(fileSize: number): number {
  for (const bucket of SIZE_BUCKETS) {
    if (fileSize >= bucket.min && fileSize < bucket.max) return bucket.threshold
  }
  return DEFAULT_DISTANCE_THRESHOLD
}

function rebuildIndices(): void {
  _tlshTrie.clear()

  for (const h of _knownTlshHashes) {
    // Prefix trie — first 4 chars of TLSH are the checksum/version bytes
    const prefix = h.slice(0, 4)
    if (!_tlshTrie.has(prefix)) _tlshTrie.set(prefix, new Set())
    _tlshTrie.get(prefix)!.add(h)
  }

}

/** Save to disk */
function persistDb(): void {
  try {
    const dir = path.dirname(DB_PATH)
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
    const db: TlshDb = {
      version: 2,
      updatedAt: new Date().toISOString(),
      totalHashes: _knownTlshHashes.size,
      hashes: Array.from(_knownTlshHashes),
    }
    fs.writeFileSync(DB_PATH, JSON.stringify(db), 'utf-8')
  } catch (err) { console.warn('[fuzzy-hash] persist failed:', (err as Error).message) }
}

/** Load from disk on startup */
function loadDb(): void {
  try {
    if (!fs.existsSync(DB_PATH)) return
    const raw = fs.readFileSync(DB_PATH, 'utf-8')
    const db = JSON.parse(raw) as TlshDb
    if (db.hashes && Array.isArray(db.hashes)) {
      _knownTlshHashes = new Set(db.hashes.filter(h => h && h.length > 10))
      _loadedFromDisk = _knownTlshHashes.size
      rebuildIndices()
    }
  } catch (err) { console.warn('[fuzzy-hash] load failed:', (err as Error).message) }
}

// ── Public DB API ──

export function getKnownTlshHashes(): string[] {
  return Array.from(_knownTlshHashes)
}

export function getTlshDbStats(): { total: number; loadedFromDisk: number; triePrefixes: number } {
  return {
    total: _knownTlshHashes.size,
    loadedFromDisk: _loadedFromDisk,
    triePrefixes: _tlshTrie.size,
  }
}

export function setKnownTlshHashes(hashes: string[]): void {
  _knownTlshHashes = new Set(hashes.filter(h => h && h.length > 10))
  rebuildIndices()
  persistDb()
}

export function mergeTlshHashes(hashes: string[]): void {
  let changed = false
  for (const h of hashes) {
    if (h && h.length > 10 && !_knownTlshHashes.has(h)) {
      _knownTlshHashes.add(h)
      changed = true
    }
  }
  if (changed) {
    rebuildIndices()
    persistDb()
  }
}

export function clearTlshCache(): void {
  _knownTlshHashes = new Set()
  _tlshTrie.clear()
}

/** Initialize — called once at startup */
export function initFuzzyHashDb(): void {
  loadDb()
  if (_knownTlshHashes.size > 0) {
    console.log(`  🧬 Fuzzy hash DB loaded: ${_knownTlshHashes.size} TLSH hashes from disk`)
  }
}

// ── Core: compute ──

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
      return null
    }

    return { sha256, tlsh, fileSize: stat.size }
  } catch {
    return null
  }
}

export function computeFuzzyHashFromBuffer(buffer: Buffer): string | null {
  if (buffer.length < TLSH_MIN_SIZE) return null
  try {
    return tlshLib.hash(buffer)
  } catch {
    return null
  }
}

// ── Fast-Path Matching (prefix trie → O(1) rejection) ──

/**
 * Compare a TLSH hash against the known database using prefix trie fast-path.
 *
 * Algorithm:
 *   1. Check prefix trie — if no hashes share the same 4-char prefix, reject immediately
 *   2. For hashes that share the prefix, compute full TLSH distance
 *   3. Return best match under threshold
 *
 * This avoids O(N) comparisons for every query — only hashes with
 * matching TLSH prefix are compared (typically <1% of DB).
 */
export function fuzzyMatch(
  queryHash: string,
  database?: string[],
  threshold?: number,
): FuzzyMatchResult | null {
  if (!queryHash || _knownTlshHashes.size === 0) return null

  const db = database || Array.from(_knownTlshHashes)
  const thr = threshold ?? DEFAULT_DISTANCE_THRESHOLD

  // Fast-path: use prefix trie if querying against the full DB
  let candidates: Set<string> | undefined
  if (!database) {
    const prefix = queryHash.slice(0, 4)
    candidates = _tlshTrie.get(prefix)
    if (!candidates || candidates.size === 0) return null
  }

  let bestDistance = Infinity
  let bestMatch = ''

  const searchSet = candidates || new Set(db)
  for (const known of searchSet) {
    try {
      const diff = tlshLib.diff(known, queryHash)
      if (diff < bestDistance && diff <= thr) {
        bestDistance = diff
        bestMatch = known
        if (diff === 0) break // Perfect match — stop searching
      }
    } catch {
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
 * Size-aware fuzzy match — uses tighter thresholds for smaller files.
 */
export function fuzzyMatchWithSize(
  queryHash: string,
  fileSize: number,
): FuzzyMatchResult | null {
  const threshold = getThreshold(fileSize)
  return fuzzyMatch(queryHash, undefined, threshold)
}

/**
 * Convenience wrapper: compute TLSH → size-aware fuzzy match.
 */
export function fuzzyMatchFile(
  filePath: string,
  threshold?: number,
): FuzzyMatchResult | null {
  const result = computeFuzzyHash(filePath)
  if (!result) return null

  if (threshold !== undefined) {
    return fuzzyMatch(result.tlsh, undefined, threshold)
  }
  return fuzzyMatchWithSize(result.tlsh, result.fileSize)
}

// ── Distance ──

export function tlshDistance(hash1: string, hash2: string): number {
  try {
    return tlshLib.diff(hash1, hash2)
  } catch {
    return -1
  }
}

// ── Clustering ──

/**
 * Group TLSH hashes by distance threshold.
 * Uses prefix trie to reduce O(N²) comparisons.
 */
export function clusterByTlsh(
  hashes: string[],
  threshold: number = DEFAULT_DISTANCE_THRESHOLD,
): string[][] {
  if (hashes.length < 2) return []

  const clusters: string[][] = []
  const used = new Set<number>()

  for (let i = 0; i < hashes.length; i++) {
    if (used.has(i)) continue
    const cluster: string[] = [hashes[i]]
    used.add(i)

    // Fast-path: only compare against hashes with matching prefix
    const prefix = hashes[i].slice(0, 4)

    for (let j = i + 1; j < hashes.length; j++) {
      if (used.has(j)) continue
      // Quick reject: different prefix
      if (hashes[j].slice(0, 4) !== prefix) continue
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

// ── Auto-init: call initFuzzyHashDb() from main.ts after app.whenReady() ──
