import type { BrowserWindow } from 'electron'

// ═══════════════════════════════════════════════════
// SCANNER — Shared Types & Utilities
// ═══════════════════════════════════════════════════

export type ScanMode = 'files' | 'processes' | 'cheats' | 'dma' | 'extended' | 'network'

export interface ScanResult {
  path: string
  fileName: string
  type: 'file' | 'browser' | 'process' | 'registry' | 'hardware' | 'software'
  risk: 'high' | 'medium' | 'low'
  matches: string[]
  size: number
  modifiedAt: string
}

export interface ScanProgress {
  phase: 'scanning' | 'analyzing' | 'done'
  currentDir: string
  filesFound: number
  filesScanned: number
  totalDirs: number
  dirsDone: number
}

export interface ScanResponse {
  results: ScanResult[]
  summary: {
    totalScanned: number
    suspiciousFiles: number
    highRiskCount: number
    scanTimeMs: number
  }
}

export interface HeuristicResult {
  riskScore: number
  suspicions: string[]
}

export interface GamePid {
  pid: number
  platform: 'fivem' | 'rage' | 'altv' | 'gta5'
}

export interface CheatCategory {
  names: string[]
  strings: Buffer[]
  description: string
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'WARNING'
}

// ── Dedup set — shared across all scan modes ──

export const _findingDedup = new Set<string>()

export function addFindingDedup(key: string): boolean {
  if (_findingDedup.has(key)) return false
  _findingDedup.add(key)
  return true
}

export function clearFindingDedup() {
  _findingDedup.clear()
}

// ── Shared utilities ──

export const yieldToEventLoop = () => new Promise<void>(resolve => setImmediate(resolve))

export async function sendProgress(win: BrowserWindow | null, data: ScanProgress) {
  win?.webContents.send('scan-progress', data)
  await yieldToEventLoop()
}

export const SCAN_CONCURRENCY = 4

export async function processBatch<T, R>(
  items: T[],
  fn: (item: T) => Promise<R>,
  concurrency: number = SCAN_CONCURRENCY,
): Promise<R[]> {
  const results: R[] = []
  const executing = new Set<Promise<void>>()

  for (const item of items) {
    const p = (async () => {
      const index = results.length
      results.push(await fn(item))
      return index
    })().then(() => {
      executing.delete(p)
    }) as Promise<void>

    executing.add(p)

    if (executing.size >= concurrency) {
      await Promise.race(executing)
    }
  }

  await Promise.all(executing)
  return results
}

export function execCmd(cmd: string, psCmd: string, opts = {}): string {
  const { execSync } = require('child_process')
  try {
    return execSync(cmd, { encoding: 'utf-8', timeout: 8000, ...opts })
  } catch (_e) {
    try {
      return execSync(psCmd, { encoding: 'utf-8', timeout: 8000, ...opts })
    } catch (_e) {
      return ''
    }
  }
}

// ── System paths (lazy-loaded to avoid top-level require issues) ──

export const _PF = process.env.ProgramFiles || 'C:\\Program Files'
export const _PF86 = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)'
export const _PD = process.env.ProgramData || 'C:\\ProgramData'
export const _WR = process.env.SystemRoot || 'C:\\Windows'
export const _HOME = require('os').homedir()
