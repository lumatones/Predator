/**
 * Predator — Scanner Entry Point
 *
 * Barrel module: imports scan mode functions from scanner/* modules,
 * keeps init/bootstrap logic and IPC handler registration.
 *
 * Modules:
 *   scanner/full-scan.ts      — runFullScan (12 phases)
 *   scanner/quick-scan.ts     — runQuickScan (6 phases)
 *   scanner/cleaner-scan.ts   — runCleanerScan (4 phases)
 */

import { app, ipcMain, BrowserWindow } from 'electron'

import { runPostScanPipeline } from './scan-pipeline'
import { startTelemetryQueue } from './telemetry-queue'
import { filterNoiseFindings } from './result-grouper'
import { rescoreResults } from './risk-scorer'
import { handleCancelScan } from './ipc-handlers-scan'
import { runDmaScan } from './modes/dma'
import { loadSafeFilesDb, syncSafeFilesFromServer, getSafeFilesCount } from './safe-files-db'
import { getEscalationBonus, getProfileSummary } from './persistent-profile'
import { type ScanResult, ScanMode, ScanResponse, sendProgress, ctx } from './types'

// ── Scan mode imports (extracted modules) ──
import { runFullScan } from './scanner/full-scan'
import { runQuickScan } from './scanner/quick-scan'
import { runCleanerScan } from './scanner/cleaner-scan'

// ── Re-exports ──
export { startCloudSync, stopCloudSync, fetchCheatHashes } from './cloud-sync'
export { startTelemetryQueue, stopTelemetryQueue } from './telemetry-queue'
export { runFullScan } from './scanner/full-scan'
export { runQuickScan } from './scanner/quick-scan'
export { runCleanerScan } from './scanner/cleaner-scan'

// ═══════════════════════════════════════════════════
// INIT
// ═══════════════════════════════════════════════════

interface ScanOptions {
  token_id?: number
  tokenId?: number
  pc_username?: string
  pcUsername?: string
}

export async function initSafeFilesDb(): Promise<void> {
  loadSafeFilesDb()
  try {
    const count = await syncSafeFilesFromServer()
    console.log(`  📁 Safe files DB ready: ${getSafeFilesCount()} entries (${count} new from server)`)
  } catch (err) { console.warn('[scanner] safe-files server sync failed:', (err as Error).message) }
}

export function initTelemetry(): void {
  startTelemetryQueue()
  console.log('  📤 Telemetry queue started')
}

// ═══════════════════════════════════════════════════
// IPC HANDLERS
// ═══════════════════════════════════════════════════

export function registerScanHandlers() {
  ipcMain.handle('cancel-scan', async () => {
    const result = handleCancelScan(ctx.abortController)
    if (result.success) {
      console.log('  Scan cancelled by user')
    }
    return result
  })

  ipcMain.handle('start-scan', async (event, mode: ScanMode, options?: ScanOptions) => {
    const win = BrowserWindow.fromWebContents(event.sender)
    const tokenId = options?.token_id ?? options?.tokenId ?? 0
    const pcUsername = options?.pc_username ?? options?.pcUsername ?? 'unknown'

    const escalationBonus = getEscalationBonus()
    const profile = getProfileSummary()
    if (escalationBonus > 0) {
      console.log(`  📈 Profile ESCALATED: ${profile.consistencyPercent}% consistency over last scans — adding +${escalationBonus} to all findings`)
    }
    ctx.escalationBonus = escalationBonus
    const scanController = ctx.resetScan()

    try {
      const startTime = Date.now()
      let result: { results: ScanResult[]; filesScanned: number }

      switch (mode) {
        case 'full': result = await runFullScan(win); break
        case 'quick': result = await runQuickScan(win); break
        case 'dma': result = await runDmaScan(win); break
        case 'cleaner': result = await runCleanerScan(win); break
        default: result = { results: [], filesScanned: 0 }
      }

      if (!Array.isArray(result.results)) result.results = []

      await sendProgress(win, { phase: 'done', currentDir: '', filesFound: result.results.length, filesScanned: result.filesScanned, totalDirs: 1, dirsDone: 1 })

      // E18: Apply weighted risk re-scoring before filtering.
      // Critical findings may be promoted by scoring, so filtering raw results
      // would make the displayed list disagree with the weighted result state.
      const scoredResults = rescoreResults(result.results)
      const filteredResults = filterNoiseFindings(scoredResults)
      const summary = {
        totalScanned: result.filesScanned,
        suspiciousFiles: filteredResults.length,
        highRiskCount: filteredResults.filter(r => r.risk === 'critical' || r.risk === 'high').length,
        scanTimeMs: Date.now() - startTime,
      }
      const filteredCount = scoredResults.length - filteredResults.length
      if (filteredCount > 0) {
        console.log(`  🔇 Filtered ${filteredCount} noise findings (${result.results.length} → ${filteredResults.length} shown to user)`)
      }

      await runPostScanPipeline(scoredResults, summary, { tokenId, pcUsername, mode, startTime, clientVersion: app.getVersion() })
      return { results: filteredResults, summary } satisfies ScanResponse
    } catch (err) {
      console.error(`Scan error (${mode}):`, err)
      return { results: [], summary: { totalScanned: 0, suspiciousFiles: 0, highRiskCount: 0, scanTimeMs: 0 } } satisfies ScanResponse
    } finally {
      ctx.finishScan(scanController)
    }
  })
}
