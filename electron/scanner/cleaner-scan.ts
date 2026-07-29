/**
 * Predator — Cleaner Scan (4 phases)
 *
 * Extracted from scanner.ts. PC cleaner / forensic integrity check.
 */

import { BrowserWindow } from 'electron'
import { runAntiTamperScan } from '../anti-tamper'
import { runPcCleanerScan } from '../pc-cleaner-detection'
import { runAntiForensicScan } from '../anti-forensic'
import { runForensicScan } from '../forensic-traces'
import { checkIommuStatus } from '../modes/dma'
import { safeCall } from '../utils/safe-spread'
import { type ScanResult, sendProgress, clearFindingDedup, ctx } from '../types'

export async function runCleanerScan(win: BrowserWindow | null): Promise<{ results: ScanResult[]; filesScanned: number }> {
  const results: ScanResult[] = []
  const signal = ctx.abortController?.signal
  const aborted = () => signal?.aborted ?? false

  clearFindingDedup()

  results.push(...safeCall('runAntiTamperScan', () => runAntiTamperScan()))
  if (aborted()) return { results, filesScanned: 0 }

  await sendProgress(win, { phase: 'scanning', currentDir: 'PC cleaning detection...', filesFound: results.length, filesScanned: 0, totalDirs: 4, dirsDone: 1 })
  results.push(...safeCall('runPcCleanerScan', () => runPcCleanerScan()))
  if (aborted()) return { results, filesScanned: 0 }

  await sendProgress(win, { phase: 'scanning', currentDir: 'Anti-forensic integrity check...', filesFound: results.length, filesScanned: 0, totalDirs: 4, dirsDone: 2 })
  results.push(...safeCall('runAntiForensicScan', () => runAntiForensicScan()))
  if (aborted()) return { results, filesScanned: 0 }

  await sendProgress(win, { phase: 'scanning', currentDir: 'Forensic artifact scan...', filesFound: results.length, filesScanned: 0, totalDirs: 4, dirsDone: 3 })
  results.push(...safeCall('runForensicScan', () => runForensicScan()))
  if (aborted()) return { results, filesScanned: 0 }

  await sendProgress(win, { phase: 'scanning', currentDir: 'IOMMU / DMA integrity...', filesFound: results.length, filesScanned: 0, totalDirs: 4, dirsDone: 4 })
  results.push(...safeCall('checkIommuStatus', () => checkIommuStatus()))

  await sendProgress(win, { phase: 'done', currentDir: '', filesFound: results.length, filesScanned: results.length, totalDirs: 4, dirsDone: 4 })
  return { results, filesScanned: 0 }
}
