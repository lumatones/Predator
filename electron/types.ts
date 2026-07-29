import type { BrowserWindow } from 'electron'
import type { PeAnalysisResult, SectionEntropy } from './cheat-rules'
import { execSync } from 'child_process'
import os from 'os'

// ═══════════════════════════════════════════════════
// SCANNER — Shared Types & Utilities
// ═══════════════════════════════════════════════════

export type ScanMode = 'full' | 'quick' | 'dma' | 'cleaner'

export interface ScanResult {
  path: string
  fileName: string
  type: 'file' | 'browser' | 'process' | 'registry' | 'hardware' | 'software' | 'system'
  risk: 'critical' | 'high' | 'medium' | 'low'
  matches: string[]
  size: number
  modifiedAt: string
  /** SHA256 hash of the file (expensive — only for HIGH-risk .exe/.dll/.sys) */
  sha256?: string
  /** Partial hash (first 64KB SHA256) — fast, computed for ALL file results */
  partialHash?: string
  /** Whether the file has a valid digital signature (only for .exe/.dll/.sys) */
  hasValidSignature?: boolean
  /** Rule name for shadow-mode findings (telemetry grouping) */
  ruleName?: string
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
  /** Shadow-mode rule hits — silent telemetry, never shown to user */
  shadowRuleHits?: string[]
  /** Digital signature validity (only for .exe/.dll/.sys) */
  hasValidSignature?: boolean
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
  shadow?: boolean
}

// ── ScanContext — shared mutable state across scan modes ──

export class ScanContext {
  findingDedup = new Set<string>()
  sigCache = new Map<string, boolean>()
  peHeaderCache = new Map<string, { peInfo: PeAnalysisResult | null; secEntropy: SectionEntropy[]; mtime: number; filepath: string }>()
  cheatNameCache = new Map<string, string[]>()
  /** Shadow-mode findings: collect silently, never flag the user */
  shadowFindings: ScanResult[] = []
  /** Track mtime for incremental scan */
  fileMtimeCache = new Map<string, number>()
  /** AbortController for scan cancellation */
  abortController: AbortController | null = null
  /** Persistent profile escalation bonus (0 = not escalated) */
  escalationBonus: number = 0

  readonly PE_CACHE_MAX = 500

  addFinding(key: string): boolean {
    if (this.findingDedup.has(key)) return false
    this.findingDedup.add(key)
    return true
  }

  clear() {
    // Full reset — clears ALL state (use for app restart / full reset)
    this.findingDedup.clear()
    this.sigCache.clear()
    this.peHeaderCache.clear()
    this.cheatNameCache.clear()
    this.shadowFindings = []
  }

  /** Reset scan-specific state but PRESERVE expensive caches (signatures, PE headers).
   *  Digital signatures don't change between scans — no need to re-check via PowerShell.
   *  sigCache → 2s per file saved on subsequent scans. */
  resetScan() {
    this.findingDedup.clear()
    this.cheatNameCache.clear()
    this.shadowFindings = []
    // Create new AbortController for this scan
    this.abortController?.abort() // Cancel any previous scan
    this.abortController = new AbortController()
    // NOTE: sigCache and peHeaderCache intentionally NOT cleared
  }
}

/** Global scan context instance */
export const ctx = new ScanContext()

// ── Backward compatibility aliases (deprecated, use ctx instead) ──

export const _findingDedup = ctx.findingDedup

export function addFindingDedup(key: string): boolean {
  return ctx.addFinding(key)
}

export function clearFindingDedup() {
  ctx.findingDedup.clear()
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

// ── System paths ──

export const _PF = process.env.ProgramFiles || 'C:\\Program Files'
export const _PF86 = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)'
export const _PD = process.env.ProgramData || 'C:\\ProgramData'
export const _WR = process.env.SystemRoot || 'C:\\Windows'
export const _HOME = os.homedir()

// ── PowerShell JSON utility ──

/** Parse PowerShell JSON output: handles single object vs array, empty output */
/** Check if a file has changed since last scan (incremental scan support) */
export function hasFileChanged(ctx: ScanContext, filepath: string, currentMtime: number): boolean {
  const cached = ctx.fileMtimeCache.get(filepath)
  if (cached === undefined) {
    ctx.fileMtimeCache.set(filepath, currentMtime)
    return true // first time seeing this file — scan it
  }
  return currentMtime !== cached
}

/** Update mtime cache for a file after scanning */
export function markFileScanned(ctx: ScanContext, filepath: string, mtime: number): void {
  ctx.fileMtimeCache.set(filepath, mtime)
}

export function parsePsJson<T>(out: string): T[] {
  if (!out || out.trim().length < 5) return []
  try {
    const parsed = JSON.parse(out)
    return Array.isArray(parsed) ? parsed : [parsed]
  } catch {
    return []
  }
}
