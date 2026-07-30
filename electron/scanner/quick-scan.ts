/**
 * Predator — Quick Scan (6 phases)
 *
 * Extracted from scanner.ts. Lightweight scan for fast triage.
 */

import { BrowserWindow } from 'electron'
import { scanRunningProcessesV2, scanNamedPipes, scanWmiPersistence } from '../modes/processes'
import { scanMasqueradingProcesses } from '../modes/games'
import { scanPrefetchV2, scanRegistryDeepV2, scanRegistryForCheats } from '../modes/registry'
import { scanNetstatV2 } from '../modes/network'
import { scanBrowserHistory } from '../modes/browser'
import { runAntiTamperScan } from '../anti-tamper'
import { safeCall, safeSpread } from '../utils/safe-spread'
import { QUICK_CHEAT_KEYWORDS } from '../signature-registry'
import { type ScanResult, sendProgress, clearFindingDedup, ctx } from '../types'

export async function runQuickScan(win: BrowserWindow | null): Promise<{ results: ScanResult[]; filesScanned: number }> {
  const results: ScanResult[] = []
  const filesScanned = 0
  const signal = ctx.abortController?.signal
  const aborted = () => signal?.aborted ?? false

  clearFindingDedup()

  results.push(...safeCall('runAntiTamperScan', () => runAntiTamperScan()))
  if (aborted()) return { results, filesScanned }

  await sendProgress(win, { phase: 'scanning', currentDir: 'Processes...', filesFound: results.length, filesScanned, totalDirs: 5, dirsDone: 1 })
  results.push(...safeCall('scanRunningProcessesV2', () => scanRunningProcessesV2()))
  results.push(...safeCall('scanMasqueradingProcesses', () => scanMasqueradingProcesses()))
  if (aborted()) return { results, filesScanned }

  await sendProgress(win, { phase: 'scanning', currentDir: 'Prefetch...', filesFound: results.length, filesScanned, totalDirs: 5, dirsDone: 2 })
  results.push(...safeCall('scanPrefetchV2', () => scanPrefetchV2()))
  if (aborted()) return { results, filesScanned }

  await sendProgress(win, { phase: 'scanning', currentDir: 'Registry...', filesFound: results.length, filesScanned, totalDirs: 5, dirsDone: 3 })
  results.push(...safeCall('scanRegistryDeepV2', () => scanRegistryDeepV2()))
  results.push(...safeCall('scanRegistryForCheats', () => scanRegistryForCheats()))
  if (aborted()) return { results, filesScanned }

  await sendProgress(win, { phase: 'scanning', currentDir: 'Pipes & persistence...', filesFound: results.length, filesScanned, totalDirs: 6, dirsDone: 4 })
  results.push(...safeCall('scanNamedPipes', () => scanNamedPipes()))
  results.push(...safeCall('scanWmiPersistence', () => scanWmiPersistence()))
  if (aborted()) return { results, filesScanned }

  await sendProgress(win, { phase: 'scanning', currentDir: 'Network...', filesFound: results.length, filesScanned, totalDirs: 6, dirsDone: 5 })
  results.push(...safeCall('scanNetstatV2', () => scanNetstatV2()))
  if (aborted()) return { results, filesScanned }

  await sendProgress(win, { phase: 'scanning', currentDir: 'Browser history...', filesFound: results.length, filesScanned, totalDirs: 6, dirsDone: 6 })
  try {
    const bh = await scanBrowserHistory(QUICK_CHEAT_KEYWORDS)
    results.push(...safeSpread('scanBrowserHistory', bh))
  } catch (err) { console.error('[scan] scanBrowserHistory crashed:', (err as Error).message || err) }

  await sendProgress(win, { phase: 'done', currentDir: '', filesFound: results.length, filesScanned: results.length, totalDirs: 6, dirsDone: 6 })
  return { results, filesScanned: results.length }
}
