/**
 * Predator — Signature Watcher
 *
 * Hot-reload cheat signatures at runtime WITHOUT restarting the app.
 *
 * Two sources:
 *   1. Local file: watches a `signatures.json` in the user data directory
 *      (can be updated by external tools, manual edits, etc.)
 *   2. Server API: polls `GET /api/v1/signatures` every 5 minutes
 *      for the latest cheat keywords and regex patterns
 *
 * When new signatures arrive:
 *   - Keywords are merged into ALL_CHEAT_KEYWORDS (deduped)
 *   - Patterns are merged into SUSPICIOUS_PATTERNS (deduped)
 *   - IPC event `signatures-updated` is sent to the renderer
 */

import fs from 'fs'
import path from 'path'
import http from 'http'
import https from 'https'
import { BrowserWindow, app } from 'electron'
import { addKeywords, addPatterns, getSignatureStats } from './signature-registry'
import { getApiBase } from './config'

interface SignaturePayload {
  version: number
  updatedAt: string
  keywords: string[]
  patterns: string[] // regex source strings, e.g. "[Nn]ightfall"
}

let _fileWatcher: fs.FSWatcher | null = null
let _pollTimer: ReturnType<typeof setInterval> | null = null
let _lastPollVersion = 0
let _mainWindow: BrowserWindow | null = null

const SIGNATURES_FILE = path.join(app?.getPath('userData') || process.cwd(), 'signatures.json')

// ═══════════════════════════════════════════════════
// 1. LOCAL FILE WATCHER
// ═══════════════════════════════════════════════════

function loadLocalSignatures(): void {
  try {
    if (!fs.existsSync(SIGNATURES_FILE)) return
    const raw = fs.readFileSync(SIGNATURES_FILE, 'utf-8')
    const payload = JSON.parse(raw) as SignaturePayload
    applySignaturePayload(payload, 'local file')
  } catch {
    // Invalid JSON — ignore, don't crash
  }
}

/**
 * NOTE: fs.watch is unreliable on Windows (misses events, race conditions).
 * The 5-minute server poll is the primary sync mechanism.
 * Local file watch is a best-effort convenience.
 */
function watchLocalSignatures(): void {
  // Ensure parent directory exists
  const dir = path.dirname(SIGNATURES_FILE)
  if (!fs.existsSync(dir)) {
    try { fs.mkdirSync(dir, { recursive: true }) } catch (err) { console.warn('[signature-watcher] failed:', (err as Error).message) }
  }

  try {
    _fileWatcher = fs.watch(SIGNATURES_FILE, (eventType) => {
      if (eventType === 'change') {
        console.log('  🔄 signatures.json changed — reloading...')
        loadLocalSignatures()
      }
    })
    console.log(`  📁 Watching signatures file: ${SIGNATURES_FILE}`)
  } catch {
    console.log('  ⚠️  File watch unavailable for signatures.json')
  }
}

// ═══════════════════════════════════════════════════
// 2. SERVER API POLLER
// ═══════════════════════════════════════════════════

async function fetchSignaturesFromServer(): Promise<SignaturePayload | null> {
  try {
    const base = getApiBase()
    const url = new URL('/api/v1/signatures', base)
    if (_lastPollVersion > 0) {
      url.searchParams.set('since_version', String(_lastPollVersion))
    }

    const data = await new Promise<string>((resolve, reject) => {
      const transport = url.protocol === 'https:' ? https : http
      const req = transport.get(url, (res) => {
        // 304 Not Modified — no new signatures
        if (res.statusCode === 304) return resolve('')
        let body = ''
        res.on('data', (chunk: string) => body += chunk)
        res.on('end', () => resolve(body))
        res.on('error', reject)
      })
      req.on('error', reject)
      req.setTimeout(5000, () => { req.destroy(); reject(new Error('timeout')) })
    })

    if (!data) return null
    return JSON.parse(data) as SignaturePayload
  } catch (err) {
    // Network errors are expected occasionally (server offline, etc.)
    // Only log once per 10 failures to avoid noise
    console.warn(`  ⚠️  Signature poll failed (server may be offline): ${(err as Error).message || err}`)
    return null
  }
}

async function pollServerSignatures(): Promise<void> {
  let payload: SignaturePayload | null = null
  try {
    payload = await fetchSignaturesFromServer()
  } catch {
    return
  }

  if (!payload || payload.version <= _lastPollVersion) return

  _lastPollVersion = payload.version
  applySignaturePayload(payload, 'server API')
}

// ═══════════════════════════════════════════════════
// 3. APPLY PAYLOAD
// ═══════════════════════════════════════════════════

function applySignaturePayload(payload: SignaturePayload, source: string): void {
  const keywordCount = addKeywords(payload.keywords || [])
  const patternCount = addPatterns(
    (payload.patterns || []).map(s => new RegExp(s, 'i'))
  )
  const stats = getSignatureStats()

  console.log(
    `  ☁️  Hot-reloaded sigs from ${source}: ` +
    `+${keywordCount} keywords, +${patternCount} patterns ` +
    `(${stats.keywords} total keywords, ${stats.patterns} patterns)`
  )

  // Notify renderer
  try {
    _mainWindow?.webContents.send('signatures-updated', {
      source,
      keywordsAdded: keywordCount,
      patternsAdded: patternCount,
      totalKeywords: stats.keywords,
      totalPatterns: stats.patterns,
      timestamp: new Date().toISOString(),
    })
  } catch { /* window may be gone */ }
}

// ═══════════════════════════════════════════════════
// 4. LIFECYCLE
// ═══════════════════════════════════════════════════

export function startSignatureWatcher(win: BrowserWindow): void {
  _mainWindow = win

  // Initial load from local file (if exists)
  loadLocalSignatures()

  // Watch local file for changes
  watchLocalSignatures()

  // Poll server every 5 minutes
  pollServerSignatures()
  _pollTimer = setInterval(pollServerSignatures, 5 * 60 * 1000)

  const stats = getSignatureStats()
  console.log(
    `  🔍 Signature watcher started: ` +
    `${stats.keywords} keywords, ${stats.patterns} patterns, ${stats.categories} categories`
  )
}

export function stopSignatureWatcher(): void {
  if (_fileWatcher) {
    _fileWatcher.close()
    _fileWatcher = null
  }
  if (_pollTimer) {
    clearInterval(_pollTimer)
    _pollTimer = null
  }
  _mainWindow = null
}
