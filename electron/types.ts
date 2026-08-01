import type { BrowserWindow } from 'electron'
import type { PeAnalysisResult, SectionEntropy } from './cheat-rules'
import { execWithTimeout } from './utils/exec'
// ═══════════════════════════════════════════════════
// SCANNER — Shared Types & Utilities
// ═══════════════════════════════════════════════════

export type ScanMode = 'full' | 'quick' | 'dma' | 'cleaner'

/** Structured, auditable evidence attached to a finding after scoring. */
export interface EvidenceRecord {
  id: string
  source: string
  category: string
  weight: number
  confidence: number
  explanation: string
  raw: string
  timestamp: string
  relatedFindingIds?: string[]
}

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
  /** Structured evidence; optional for backwards compatibility with older detectors/reports. */
  evidence?: EvidenceRecord[]
  /** Stable identifier used when linking evidence across findings. */
  findingId?: string
  /** Explainable per-finding weighted score, when scoring has completed. */
  riskScore?: number
  /** Human-readable summary of why this finding received its score. */
  riskExplanation?: string
}

export interface ScanProgress {
  phase: 'scanning' | 'analyzing' | 'done'
  currentDir: string
  filesFound: number
  filesScanned: number
  totalDirs: number
  dirsDone: number
}

export type ScanStatus = 'complete' | 'inconclusive'

export interface ScanDiagnostic {
  detectorId: string
  status: 'failed' | 'timeout' | 'unsupported'
  errorCode?: string
  errorMessage?: string
}

/** Internal result returned by a scan mode before the final IPC response. */
export interface ScanRunResult {
  results: ScanResult[]
  filesScanned: number
  diagnostics?: ScanDiagnostic[]
}

export interface ScanResponse {
  results: ScanResult[]
  summary: {
    totalScanned: number
    suspiciousFiles: number
    highRiskCount: number
    scanTimeMs: number
    /** A missing value is treated as complete by older renderer clients. */
    status?: ScanStatus
    diagnostics?: ScanDiagnostic[]
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
  /** True until the owning scan reaches its finally block. */
  scanActive = false
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
    this.abortController = null
    this.scanActive = false
  }

  /** Reset scan-specific state but PRESERVE expensive caches (signatures, PE headers).
   *  Digital signatures don't change between scans — no need to re-check via PowerShell.
   *  sigCache → 2s per file saved on subsequent scans. */
  resetScan(): AbortController {
    this.findingDedup.clear()
    this.cheatNameCache.clear()
    this.shadowFindings = []
    // Create new AbortController for this scan
    this.abortController?.abort() // Cancel any previous scan
    const controller = new AbortController()
    this.abortController = controller
    this.scanActive = true
    // NOTE: sigCache and peHeaderCache intentionally NOT cleared
    return controller
  }

  /** Start a background scan only when no other scan currently owns the context. */
  tryStartScan(): AbortController | null {
    if (this.scanActive) return null
    this.findingDedup.clear()
    this.cheatNameCache.clear()
    this.shadowFindings = []
    const controller = new AbortController()
    this.abortController = controller
    this.scanActive = true
    return controller
  }

  /** Mark a scan as finished only if it still owns the active controller. */
  finishScan(controller: AbortController) {
    if (this.abortController === controller) {
      this.abortController = null
      this.scanActive = false
    }
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

export function execCmd(cmd: string, psCmd: string, opts: { timeout?: number; windowsHide?: boolean } = {}): string {
  try {
    return execWithTimeout(cmd, { timeout: opts.timeout ?? 8000, windowsHide: opts.windowsHide }) || ''
  } catch (_e) {
    try {
      return execWithTimeout(psCmd, { timeout: opts.timeout ?? 8000, windowsHide: opts.windowsHide }) || ''
    } catch (_e) {
      return ''
    }
  }
}

// ── System paths (single source of truth: config.ts CFG) ──
import { CFG } from './config'
export { CFG } from './config'
/** @deprecated Use CFG.PF instead */ export const _PF = CFG.PF
/** @deprecated Use CFG.PF86 instead */ export const _PF86 = CFG.PF86
/** @deprecated Use CFG.PD instead */ export const _PD = CFG.PD
/** @deprecated Use CFG.WR instead */ export const _WR = CFG.WR
/** @deprecated Use CFG.HOME instead */ export const _HOME = CFG.HOME

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
