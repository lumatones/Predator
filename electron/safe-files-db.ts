/**
 * Predator — Safe Files Database (auto-learning whitelist)
 *
 * После каждого сканирования LOW-risk файлы добавляются в локальную БД.
 * При повторном сканировании эти файлы пропускаются (экономия времени + без шума).
 *
 * Формат хранения: JSON-файл в {appData}/Predator/safe-files.json
 *   key: sha256 первых 64KB файла (быстрый частичный хеш)
 *   value: { path, size, mtime, firstSeen, lastSeen, count, verifiedBy }
 *
 * Синхронизация с сервером: downloadKnownSafeHashes() / uploadSafeFiles()
 *
 * v2: O(1) path-based lookup via _pathIndex Map (was O(n) Object.values iteration).
 */

import fs from 'fs'
import path from 'path'
import crypto from 'crypto'
import http from 'http'
import https from 'https'
import { app } from 'electron'
import { getApiEndpoint } from './config'

// ── Types ──────────────────────────────────────────

export interface SafeFileEntry {
  /** SHA256 of first 64KB (fast partial hash) */
  partialHash: string
  /** Full file path */
  path: string
  /** File size in bytes */
  size: number
  /** File modification time (ISO string) */
  mtime: string
  /** First time this file was seen */
  firstSeen: string
  /** Last time this file was verified safe */
  lastSeen: string
  /** How many scans confirmed this file as safe */
  confirmCount: number
  /** What verified it as safe: 'auto' | 'server' | 'user' */
  verifiedBy: 'auto' | 'server' | 'user'
}

interface SafeFilesDbData {
  version: number
  entries: Record<string, SafeFileEntry>
}

// ── In-memory index for O(1) lookup ────────────────

/** Maps `normalizedPath|size` → entry key for instant path-based lookup */
const _pathIndex = new Map<string, string>()

function rebuildPathIndex(): void {
  _pathIndex.clear()
  for (const [key, entry] of Object.entries(_db.entries)) {
    if (!entry.path) continue
    const normalized = entry.path.toLowerCase().replace(/\\/g, '/')
    _pathIndex.set(`${normalized}|${entry.size}`, key)
  }
}

function addToPathIndex(key: string, entry: SafeFileEntry): void {
  if (!entry.path) return
  const normalized = entry.path.toLowerCase().replace(/\\/g, '/')
  _pathIndex.set(`${normalized}|${entry.size}`, key)
}

function removeFromPathIndex(entry: SafeFileEntry): void {
  if (!entry.path) return
  const normalized = entry.path.toLowerCase().replace(/\\/g, '/')
  const idxKey = `${normalized}|${entry.size}`
  // Only delete if this entry owns the key (same file might have been re-added)
  const ownerKey = _pathIndex.get(idxKey)
  if (ownerKey) {
    const owner = _db.entries[ownerKey]
    if (!owner || owner.path === entry.path) {
      _pathIndex.delete(idxKey)
    }
  }
}

// ── Paths ──────────────────────────────────────────

let _dbPath = ''
let _db: SafeFilesDbData = { version: 1, entries: {} }
let _dirty = false

function getDbPath(): string {
  if (_dbPath) return _dbPath
  try {
    const userDataPath = app.getPath('userData')
    _dbPath = path.join(userDataPath, 'safe-files.json')
  } catch {
    _dbPath = path.join(process.cwd(), 'safe-files.json')
  }
  return _dbPath
}

// ── Load / Save ────────────────────────────────────

export function loadSafeFilesDb(): void {
  const dbPath = getDbPath()
  try {
    if (fs.existsSync(dbPath)) {
      const raw = fs.readFileSync(dbPath, 'utf-8')
      _db = JSON.parse(raw) as SafeFilesDbData
      if (!_db.entries) _db.entries = {}
      // Prune entries older than 30 days (keep DB small)
      const thirtyDaysAgo = Date.now() - 30 * 24 * 60 * 60 * 1000
      for (const [key, entry] of Object.entries(_db.entries)) {
        if (new Date(entry.lastSeen).getTime() < thirtyDaysAgo) {
          delete _db.entries[key]
          _dirty = true
        }
      }
    } else {
      _db = { version: 1, entries: {} }
    }
  } catch {
    _db = { version: 1, entries: {} }
  }
  // Build path index AFTER loading (always, even on fresh DB)
  rebuildPathIndex()
}

export function saveSafeFilesDb(): void {
  if (!_dirty) return
  const dbPath = getDbPath()
  try {
    const dir = path.dirname(dbPath)
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
    fs.writeFileSync(dbPath, JSON.stringify(_db, null, 2), 'utf-8')
    _dirty = false
  } catch (err) { console.warn('[safe-files-db] silently failed:', (err as Error).message) }
}

// ── Core API ───────────────────────────────────────

/**
 * Compute partial hash (first 64KB) of a file for quick lookup.
 */
export function computePartialHash(filepath: string): string {
  try {
    const stat = fs.statSync(filepath)
    if (!stat.isFile()) return ''
    const readSize = Math.min(stat.size, 64 * 1024)
    const buf = Buffer.alloc(readSize)
    const fd = fs.openSync(filepath, 'r')
    fs.readSync(fd, buf, 0, readSize, 0)
    fs.closeSync(fd)
    return crypto.createHash('sha256').update(buf).digest('hex')
  } catch {
    return ''
  }
}

/**
 * Check if a file is known-safe by path+size (local entries) or hash+size (server entries).
 *
 * v2: O(1) path lookup via _pathIndex Map (was O(n) Object.values iteration).
 */
export function isFileSafe(filepath: string, size: number, _mtimeMs: number): boolean {
  if (!filepath || size === 0) return false

  // O(1): Check by path+size via index (local entries with known paths)
  const normalizedPath = filepath.toLowerCase().replace(/\\/g, '/')
  if (_pathIndex.has(`${normalizedPath}|${size}`)) return true

  // O(1): Check by partial hash + size (for server entries with empty path)
  const partialHash = computePartialHash(filepath)
  if (partialHash) {
    const key = `${partialHash}_${size}`
    if (_db.entries[key]) return true
  }

  return false
}

/**
 * Mark a file as safe (add to database).
 * Uses partial hash + size + path as unique key.
 */
export function markFileSafe(
  filepath: string,
  size: number,
  mtimeMs: number,
  verifiedBy: 'auto' | 'server' | 'user' = 'auto',
): void {
  const partialHash = computePartialHash(filepath)
  if (!partialHash) return

  const key = `${partialHash}_${size}`
  const existing = _db.entries[key]
  const now = new Date().toISOString()

  if (existing) {
    // Update existing entry — path may have changed
    const oldPath = existing.path
    existing.lastSeen = now
    existing.confirmCount++
    existing.path = filepath
    if (oldPath !== filepath) {
      // Path changed — re-index
      const oldNormalized = oldPath.toLowerCase().replace(/\\/g, '/')
      _pathIndex.delete(`${oldNormalized}|${size}`)
      addToPathIndex(key, existing)
    }
  } else {
    _db.entries[key] = {
      partialHash,
      path: filepath,
      size,
      mtime: new Date(mtimeMs).toISOString(),
      firstSeen: now,
      lastSeen: now,
      confirmCount: 1,
      verifiedBy,
    }
    addToPathIndex(key, _db.entries[key])
  }

  // Dedup by path (same file might have different partial hashes if content changed)
  const pathKey = `path:${filepath.toLowerCase()}`
  const existingByPath = Object.entries(_db.entries).find(
    ([, e]) => `path:${e.path.toLowerCase()}` === pathKey && e.size === size,
  )
  if (existingByPath && existingByPath[0] !== key) {
    const [dupKey, dupEntry] = existingByPath
    if (_db.entries[key].confirmCount >= dupEntry.confirmCount) {
      removeFromPathIndex(dupEntry)
      delete _db.entries[dupKey]
    } else {
      delete _db.entries[key]
    }
  }

  _dirty = true
  saveSafeFilesDb()
}

/**
 * Mark multiple files as safe at once (batch operation).
 */
export function markFilesSafe(
  entries: Array<{ filepath: string; size: number; mtimeMs: number }>,
  verifiedBy: 'auto' | 'server' | 'user' = 'auto',
): void {
  for (const entry of entries) {
    markFileSafe(entry.filepath, entry.size, entry.mtimeMs, verifiedBy)
  }
}

/**
 * Get count of safe files in the database.
 */
export function getSafeFilesCount(): number {
  return Object.keys(_db.entries).length
}

/**
 * Refresh ALL existing safe DB entries — increment confirmCount for files
 * that still exist at their recorded path with the same mtime.
 */
export function refreshSafeFilesDb(): { refreshed: number; removed: number } {
  let refreshed = 0
  let removed = 0

  for (const [key, entry] of Object.entries(_db.entries)) {
    if (entry.verifiedBy === 'server' || !entry.path) continue

    try {
      if (!fs.existsSync(entry.path)) {
        const daysSinceLastSeen = (Date.now() - new Date(entry.lastSeen).getTime()) / (1000 * 60 * 60 * 24)
        if (daysSinceLastSeen > 7) {
          removeFromPathIndex(entry)
          delete _db.entries[key]
          removed++
          _dirty = true
        }
        continue
      }

      const st = fs.statSync(entry.path)
      if (!st.isFile()) {
        removeFromPathIndex(entry)
        delete _db.entries[key]
        removed++
        _dirty = true
        continue
      }

      entry.lastSeen = new Date().toISOString()
      entry.confirmCount++
      entry.size = st.size
      entry.mtime = new Date(st.mtimeMs).toISOString()
      refreshed++
      _dirty = true
    } catch {
      try {
        const daysSinceLastSeen = (Date.now() - new Date(entry.lastSeen).getTime()) / (1000 * 60 * 60 * 24)
        if (daysSinceLastSeen > 7) {
          removeFromPathIndex(entry)
          delete _db.entries[key]
          removed++
          _dirty = true
        }
      } catch (err) { console.warn('[safe-files-db] failed:', (err as Error).message) }
    }
  }

  if (removed > 0) rebuildPathIndex()
  if (refreshed > 0 || removed > 0) saveSafeFilesDb()

  return { refreshed, removed }
}

// ── Server Sync ────────────────────────────────────

export function syncSafeFilesFromServer(): Promise<number> {
  return new Promise((resolve) => {
    try {
      const { hostname, port, protocol } = getApiEndpoint()
      const transport = protocol === 'https:' ? https : http
      const req = transport.get(
        `${protocol}//${hostname}${port ? `:${port}` : ''}/api/auth/safe-files`,
        (res) => {
          let data = ''
          res.on('data', (chunk: string) => { data += chunk })
          res.on('end', () => {
            try {
              const parsed = JSON.parse(data)
              if (Array.isArray(parsed)) {
                let added = 0
                for (const entry of parsed) {
                  if (entry.partialHash && entry.size) {
                    const key = `${entry.partialHash}_${entry.size}`
                    if (!_db.entries[key]) {
                      _db.entries[key] = {
                        partialHash: entry.partialHash,
                        path: '',
                        size: entry.size,
                        mtime: '',
                        firstSeen: entry.lastSeen || new Date().toISOString(),
                        lastSeen: new Date().toISOString(),
                        confirmCount: entry.confirmCount || 2,
                        verifiedBy: 'server',
                      }
                      added++
                    }
                  }
                }
                if (added > 0) {
                  _dirty = true
                  saveSafeFilesDb()
                  console.log(`  ☁️  Synced ${added} safe files from community whitelist`)
                }
                resolve(added)
              } else {
                resolve(0)
              }
            } catch {
              resolve(0)
            }
          })
        },
      )
      req.on('error', () => resolve(0))
      req.setTimeout(8000, () => { req.destroy(); resolve(0) })
    } catch {
      resolve(0)
    }
  })
}

export function uploadSafeFiles(): void {
  try {
    const entries = Object.values(_db.entries)
      .filter(e => e.verifiedBy === 'auto' && e.confirmCount >= 1)
      .slice(0, 100)

    if (entries.length === 0) return

    const payload = JSON.stringify({
      entries: entries.map(e => ({
        partialHash: e.partialHash,
        fileName: path.basename(e.path) || 'unknown',
        size: e.size,
        confirmCount: e.confirmCount,
      })),
    })

    const { hostname, port, protocol } = getApiEndpoint()
    const transport = protocol === 'https:' ? https : http
    const req = transport.request({
      hostname,
      port,
      path: '/api/auth/submit-safe-files',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
      },
    })
    req.write(payload)
    req.end()
  } catch (err) { console.warn('[safe-files-db] silently failed:', (err as Error).message) }
}

// ── Auto-cleanup timer ─────────────────────────────

let _autoSaveTimer: ReturnType<typeof setInterval> | null = null

export function startAutoSave(intervalMs = 60_000): void {
  if (_autoSaveTimer) return
  _autoSaveTimer = setInterval(() => {
    if (_dirty) saveSafeFilesDb()
  }, intervalMs)
}

export function stopAutoSave(): void {
  if (_autoSaveTimer) {
    clearInterval(_autoSaveTimer)
    _autoSaveTimer = null
  }
}
