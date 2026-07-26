/**
 * Predator — Browser History Scanner
 * Parses Chromium-based browser SQLite history databases using sql.js.
 *
 * Supported browsers:
 *   Chrome, Edge, Brave, Yandex Browser, Opera, Opera GX
 *
 * Chromium timestamp epoch: 1601-01-01 00:00:00 UTC (Windows FILETIME)
 * Convert: (microseconds - 11644473600000000) / 1000 = ms since epoch
 */

import path from 'path'
import fs from 'fs'
import { CFG } from './config'
// sql.js singleton — initialized once, reused across all scans
import initSqlJs, { Database, SqlJsStatic } from 'sql.js'

let _sqlInitialized = false
let _SQL: SqlJsStatic | null = null

/** Get or initialize the sql.js WASM singleton */
async function getSqlJs(): Promise<SqlJsStatic> {
  if (_SQL) return _SQL
  if (!_sqlInitialized) {
    _sqlInitialized = true
    _SQL = await initSqlJs()
  }
  return _SQL!
}

const { HOME } = CFG

const CHROMIUM_EPOCH_DELTA = 11644473600000000n // microseconds

interface BrowserProfile {
  name: string
  /** Path to the History SQLite file */
  historyPath: string
  /** User-readable label */
  label: string
}

export interface HistoryEntry {
  url: string
  title: string
  visitCount: number
  lastVisitTime: string   // ISO date string
  browser: string
}

export interface BrowserHistoryResult {
  browser: string
  path: string
  entries: HistoryEntry[]
  totalEntries: number
  error?: string
}

/**
 * Chromium WebKit time (microseconds since 1601-01-01) → JS Date (ms since 1970-01-01)
 *
 * Formula: (webkitTime / 1000) - 11644473600 = seconds since epoch
 * In Node: (webkitTime - 11644473600000000n) / 1000n → ms
 */
function webkitTimeToDate(webkitTime: number): Date {
  const ms = Number(BigInt(webkitTime) - CHROMIUM_EPOCH_DELTA) / 1000
  return new Date(ms)
}

/**
 * Build the list of known browser profile History paths on this machine.
 * Checks each path for existence.
 */
function getBrowserProfiles(): BrowserProfile[] {
  const localData = path.join(HOME, 'AppData', 'Local')
  const roamingData = path.join(HOME, 'AppData', 'Roaming')

  const profiles: BrowserProfile[] = [
    {
      name: 'chrome',
      historyPath: path.join(localData, 'Google', 'Chrome', 'User Data', 'Default', 'History'),
      label: 'Google Chrome',
    },
    {
      name: 'chrome_canary',
      historyPath: path.join(localData, 'Google', 'Chrome SxS', 'User Data', 'Default', 'History'),
      label: 'Chrome Canary',
    },
    {
      name: 'edge',
      historyPath: path.join(localData, 'Microsoft', 'Edge', 'User Data', 'Default', 'History'),
      label: 'Microsoft Edge',
    },
    {
      name: 'brave',
      historyPath: path.join(localData, 'BraveSoftware', 'Brave-Browser', 'User Data', 'Default', 'History'),
      label: 'Brave Browser',
    },
    {
      name: 'yandex',
      historyPath: path.join(localData, 'Yandex', 'YandexBrowser', 'User Data', 'Default', 'History'),
      label: 'Яндекс.Браузер',
    },
    {
      name: 'opera',
      historyPath: path.join(roamingData, 'Opera Software', 'Opera Stable', 'History'),
      label: 'Opera',
    },
    {
      name: 'opera_gx',
      historyPath: path.join(roamingData, 'Opera Software', 'Opera GX Stable', 'History'),
      label: 'Opera GX',
    },
  ]

  // Filter to only existing files
  return profiles.filter(p => {
    try {
      return fs.existsSync(p.historyPath) && fs.statSync(p.historyPath).size > 0
    } catch {
      return false
    }
  })
}

// ── SQLite query helpers ─────────────────────

interface DbRow {
  [key: string]: unknown
}

/**
 * Open a SQLite database and execute a query.
 * Returns all rows as an array of objects.
 */
function queryDb(db: Database, sql: string, params: unknown[] = []): DbRow[] {
  const stmt = db.prepare(sql)
  if (params.length > 0) stmt.bind(params as any)

  const rows: DbRow[] = []
  while (stmt.step()) {
    rows.push(stmt.getAsObject())
  }
  stmt.free()
  return rows
}

/**
 * Try to open a History SQLite file, returning null on failure.
 * Checks schema first to verify it's a valid Chromium History DB.
 */
function openHistory(path: string, SQL: SqlJsStatic): Database | null {
  try {
    const buffer = fs.readFileSync(path)
    if (buffer.length === 0) return null
    if (buffer.length > 50 * 1024 * 1024) return null // Sanity cap

    const db = new SQL.Database(new Uint8Array(buffer))

    // Verify schema: check for `urls` table
    const tables = queryDb(db, "SELECT name FROM sqlite_master WHERE type='table' AND name='urls'")
    if (tables.length === 0) {
      db.close()
      return null
    }

    return db
  } catch {
    return null
  }
}

// ── Main scan function ──────────────────────

/**
 * Scan a single browser profile's history for keywords.
 * Returns structured results: URLs, titles, visit times.
 */
async function scanProfile(
  profile: BrowserProfile,
  SQL: SqlJsStatic,
  keywords: string[],
): Promise<BrowserHistoryResult> {
  const result: BrowserHistoryResult = {
    browser: profile.label,
    path: profile.historyPath,
    entries: [],
    totalEntries: 0,
  }

  const db = openHistory(profile.historyPath, SQL)
  if (!db) return result

  try {
    // Build a WHERE clause for keyword matching
    // Match against url (lowercased) OR title (lowercased)
    const conditions = keywords.map(() => `(LOWER(url) LIKE ? OR LOWER(title) LIKE ?)`)
    const whereClause = conditions.join(' OR ')

    // Build params: each keyword adds two params (%keyword% for url, %keyword% for title)
    const params: string[] = []
    for (const kw of keywords) {
      const lower = `%${kw.toLowerCase()}%`
      params.push(lower, lower)
    }

    const sql = `
      SELECT url, title, visit_count, last_visit_time
      FROM urls
      WHERE ${whereClause}
      ORDER BY last_visit_time DESC
      LIMIT 200
    `

    const rows = queryDb(db, sql, params)

    for (const row of rows) {
      const url = (row.url as string) || ''
      const title = (row.title as string) || ''
      const visitCount = (row.visit_count as number) || 0
      const lastVisitTime = row.last_visit_time as number

      const date = (lastVisitTime && lastVisitTime > 0)
        ? webkitTimeToDate(lastVisitTime).toISOString()
        : new Date(0).toISOString()

      result.entries.push({
        url,
        title,
        visitCount,
        lastVisitTime: date,
        browser: profile.label,
      })
    }

    result.totalEntries = result.entries.length
  } catch (err) {
    result.error = err instanceof Error ? err.message : 'Unknown error'
  } finally {
    db.close()
  }

  return result
}

/**
 * Scan ALL browser profiles for keywords.
 * Returns results grouped by browser.
 */
export async function scanAllBrowsers(keywords: string[]): Promise<BrowserHistoryResult[]> {
  const profiles = getBrowserProfiles()
  if (profiles.length === 0) return []

  // Use the sql.js singleton (loads WASM once)
  const SQL = await getSqlJs()

  const results: BrowserHistoryResult[] = []
  for (const profile of profiles) {
    const r = await scanProfile(profile, SQL, keywords)
    results.push(r)
  }

  return results
}

/**
 * Get total count of browser profiles found on the system.
 */
export function getBrowserCount(): number {
  return getBrowserProfiles().length
}
