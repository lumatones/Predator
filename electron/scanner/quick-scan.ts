/**
 * Predator — Quick Scan (7 phases)
 *
 * Extracted from scanner.ts. Lightweight scan for fast triage.
 */

import { BrowserWindow } from 'electron'
import { scanRunningProcessesV2, scanNamedPipes, scanWmiPersistence, scanStartupFolder } from '../modes/processes'
import { scanMasqueradingProcesses } from '../modes/games'
import { scanPrefetchV2, scanRegistryDeepV2, scanRegistryForCheats } from '../modes/registry'
import { scanNetstatV2 } from '../modes/network'
import { scanBrowserHistory } from '../modes/browser'
import { scanScheduledTasks } from '../modes/dma'
import { runAntiTamperScan } from '../anti-tamper'
import { runSelfIntegrityScan } from '../self-integrity'
import { safeCall, safeSpread } from '../utils/safe-spread'
import { QUICK_CHEAT_KEYWORDS } from '../signature-registry'
import { type ScanDiagnostic, type ScanResult, type ScanRunResult, sendProgress, clearFindingDedup, ctx } from '../types'
import { runBehavioralProcessScan } from '../modules/behavior'

export async function runQuickScan(win: BrowserWindow | null): Promise<ScanRunResult> {
  const results: ScanResult[] = []
  const filesScanned = 0
  const diagnostics: ScanDiagnostic[] = []
  const signal = ctx.abortController?.signal
  const aborted = () => signal?.aborted ?? false

  clearFindingDedup()

  results.push(...safeCall('runAntiTamperScan', () => runAntiTamperScan()))
  try {
    // H2: verify own executable integrity in every scan mode (not just full)
    results.push(...await runSelfIntegrityScan())
  } catch (err) { console.error('[quick-scan] runSelfIntegrityScan crashed:', (err as Error).message) }
  if (aborted()) return { results, filesScanned, diagnostics }

  await sendProgress(win, { phase: 'scanning', currentDir: 'Processes...', filesFound: results.length, filesScanned, totalDirs: 7, dirsDone: 1 })
  // The behavioral adapter runs first and fills the shared process inventory.
  // Legacy process detectors then reuse it instead of enumerating Windows again.
  try {
    const behavioral = await runBehavioralProcessScan({
      signal,
      sessionId: `quick-behavior-${Date.now()}`,
      timeoutMs: 8_000,
    })
    results.push(...behavioral.results)
    diagnostics.push(...behavioral.engineReport.failures.map(failure => ({
      detectorId: failure.detectorId,
      status: failure.status,
      errorCode: failure.errorCode,
      errorMessage: failure.errorMessage,
    })))
    if (behavioral.engineReport.failures.length > 0) {
      console.warn('[quick-scan] behavioral process scan incomplete:', behavioral.engineReport.failures)
    }
  } catch (err) {
    if (aborted()) return { results, filesScanned, diagnostics }
    const message = err instanceof Error ? err.message : 'Behavioral process scan failed'
    diagnostics.push({ detectorId: 'behavioral-process-scanner', status: 'failed', errorCode: 'RUNNER_ERROR', errorMessage: message })
    console.warn('[quick-scan] behavioral process scan failed:', message)
  }
  results.push(...safeCall('scanRunningProcessesV2', () => scanRunningProcessesV2()))
  results.push(...safeCall('scanMasqueradingProcesses', () => scanMasqueradingProcesses()))
  if (aborted()) return { results, filesScanned, diagnostics }

  await sendProgress(win, { phase: 'scanning', currentDir: 'Prefetch...', filesFound: results.length, filesScanned, totalDirs: 7, dirsDone: 2 })
  results.push(...safeCall('scanPrefetchV2', () => scanPrefetchV2()))
  if (aborted()) return { results, filesScanned, diagnostics }

  await sendProgress(win, { phase: 'scanning', currentDir: 'Registry...', filesFound: results.length, filesScanned, totalDirs: 7, dirsDone: 3 })
  results.push(...safeCall('scanRegistryDeepV2', () => scanRegistryDeepV2()))
  results.push(...safeCall('scanRegistryForCheats', () => scanRegistryForCheats()))
  if (aborted()) return { results, filesScanned, diagnostics }

  await sendProgress(win, { phase: 'scanning', currentDir: 'Pipes & persistence...', filesFound: results.length, filesScanned, totalDirs: 7, dirsDone: 4 })
  results.push(...safeCall('scanNamedPipes', () => scanNamedPipes()))
  results.push(...safeCall('scanWmiPersistence', () => scanWmiPersistence()))
  try {
    results.push(...await scanScheduledTasks(signal))
  } catch (err) {
    if (aborted()) return { results, filesScanned, diagnostics }
    console.warn('[quick-scan] scheduled task scan failed:', (err as Error).message)
  }
  results.push(...safeCall('scanStartupFolder', () => scanStartupFolder()))
  if (aborted()) return { results, filesScanned, diagnostics }

  await sendProgress(win, { phase: 'scanning', currentDir: 'Network...', filesFound: results.length, filesScanned, totalDirs: 7, dirsDone: 5 })
  results.push(...safeCall('scanNetstatV2', () => scanNetstatV2()))
  if (aborted()) return { results, filesScanned, diagnostics }

  await sendProgress(win, { phase: 'scanning', currentDir: 'Browser history...', filesFound: results.length, filesScanned, totalDirs: 7, dirsDone: 6 })
  try {
    const bh = await scanBrowserHistory(QUICK_CHEAT_KEYWORDS)
    results.push(...safeSpread('scanBrowserHistory', bh))
  } catch (err) { console.error('[scan] scanBrowserHistory crashed:', (err as Error).message || err) }

  await sendProgress(win, { phase: 'done', currentDir: '', filesFound: results.length, filesScanned: results.length, totalDirs: 7, dirsDone: 7 })
  return { results, filesScanned: results.length, diagnostics }
}
