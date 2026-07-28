import { ipcMain, BrowserWindow } from 'electron'
import crypto from 'crypto'
import fs from 'fs'
import path from 'path'
import { execSync } from 'child_process'

import { startCloudSync, stopCloudSync, fetchCheatHashes } from './cloud-sync'
import { runPostScanPipeline } from './scan-pipeline'
import { startTelemetryQueue, stopTelemetryQueue } from './telemetry-queue'
import { filterNoiseFindings } from './result-grouper'
import { EXTENDED_SCAN_PATHS } from './constants'
import { QUICK_CHEAT_KEYWORDS } from './signature-registry'

import { scanProcessForAmsiEtw } from './modes/etw-amsi'
import { buildBehaviorProfile, profileToScanResult } from './behavior-profile'
import { scanRwxAndThreads, rwxResultToScanResult } from './rwx-scanner'
import { scanDiskVsMemory, dvmResultToScanResult } from './disk-vs-memory'

import {
  ScanResult,
  ScanMode,
  ScanResponse,
  sendProgress,
  yieldToEventLoop,
  clearFindingDedup,
  parsePsJson,
  ctx,
} from './types'

import { heuristicFileScan, batchCheckSignatures, ALL_CHEAT_KEYWORDS } from './heuristic'
import { fuzzyMatchFile } from './fuzzy-hash'

import { walkDirAsync } from './modes/files'
import { scanRunningProcessesV2, scanNamedPipes, scanWmiPersistence, scanBehavioralMasquerading } from './modes/processes'
import { scanGameIntegrity, scanGameModules, scanMasqueradingProcesses, scanOpenHandles } from './modes/games'
import { scanNetstatV2 } from './modes/network'
import { scanRegistryDeepV2, scanPrefetchV2, scanRegistryForCheats } from './modes/registry'
import { scanBrowserHistory } from './modes/browser'
import { runDmaScan, scanDmaDevices, scanScheduledTasks, checkIommuStatus } from './modes/dma'
import { runFullUsbDeviceScan } from './modes/usb-devices'
import { scanByovd } from './modes/byovd'
import { scanAntiDebug } from './modes/anti-debug'
import { safeCall, safeSpread } from './utils/safe-spread'
import { runApcScan } from './modes/apc-detector'
import { runForensicScan } from './forensic-traces'
import { runAntiForensicScan } from './anti-forensic'
import { runPcCleanerScan } from './pc-cleaner-detection'
import { loadSafeFilesDb, syncSafeFilesFromServer, getSafeFilesCount } from './safe-files-db'
import { runAntiTamperScan } from './anti-tamper'
import { runParallel } from './workers/worker-pool'
import { getEscalationBonus, getProfileSummary } from './persistent-profile'

// ═══════════════════════════════════════════════════
// FULL SCAN (was extended) — 9-phase deep scan
// ═══════════════════════════════════════════════════

/** Throw if the current scan has been cancelled. Use before expensive sync ops (PowerShell, SHA256). */
function assertNotAborted(): void {
  if (ctx.abortController?.signal.aborted) {
    throw new Error('ABORTED')
  }
}

async function runFullScan(win: BrowserWindow | null): Promise<{ results: ScanResult[]; filesScanned: number }> {
  const results: ScanResult[] = []
  let filesScanned = 0
  const signal = ctx.abortController?.signal
  const aborted = () => signal?.aborted ?? false

  clearFindingDedup()

  // ── Phase 0: Anti-Tamper Check ──
  await sendProgress(win, { phase: 'scanning', currentDir: 'Anti-tamper integrity check...', filesFound: results.length, filesScanned, totalDirs: 9, dirsDone: 0 })
  results.push(...safeCall('runAntiTamperScan', () => runAntiTamperScan()))
  if (aborted()) return { results, filesScanned }

  // Each check spawns PowerShell (2s timeout). Keeping the cache saves 2s PER FILE.
  await sendProgress(win, { phase: 'scanning', currentDir: 'Advanced process scanning...', filesFound: results.length, filesScanned, totalDirs: 9, dirsDone: 1 })
  results.push(...safeCall('scanRunningProcessesV2', () => scanRunningProcessesV2()))

  // Behavioral masquerading — detects high-memory self-spawning cheat loaders
  results.push(...safeCall('scanBehavioralMasquerading', () => scanBehavioralMasquerading()))

  // Anti-debug / RE tool detection — checks for debuggers, CheatEngine, ProcessHacker, anti-debug DLLs
  results.push(...safeCall('scanAntiDebug', () => scanAntiDebug()))

  if (aborted()) return { results, filesScanned }

  // Phase 1b — USB/PCI device inventory scan
  await sendProgress(win, { phase: 'scanning', currentDir: 'USB & PCI device inventory...', filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 2 })
  results.push(...safeCall('runFullUsbDeviceScan', () => runFullUsbDeviceScan()))
  if (aborted()) return { results, filesScanned }

  // Phase 2 — heuristic file scan (with incremental + pre-filter + fuzzy hash)
  await sendProgress(win, { phase: 'scanning', currentDir: `Heuristic file scan (${EXTENDED_SCAN_PATHS.length} directories)...`, filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 3 })
  for (const dir of EXTENDED_SCAN_PATHS) {
    await sendProgress(win, { phase: 'scanning', currentDir: dir, filesFound: results.length, filesScanned, totalDirs: 10, dirsDone: 2 })
    try {
      // Collect all file paths from directory walker
      const filePaths: string[] = []
      let dirFileCount = 0
      const DIR_FILE_LIMIT = 2000
      for await (const filePath of walkDirAsync(dir)) {
        dirFileCount++
        if (dirFileCount > DIR_FILE_LIMIT) {
          console.warn(`[Predator] Directory file limit reached: ${dir} (${dirFileCount})`)
          break
        }
        filePaths.push(filePath)
      }

      // ── BATCH: Pre-warm signature cache (1 PowerShell call for ALL binaries) ──
      // BEFORE: checkDigitalSignature() spawned PowerShell per file (2s each).
      // 500 .exe files = 1000s blocking. AFTER: 1 batch call = ~3-5s total.
      if (filePaths.length > 0) {
        const sigResults = batchCheckSignatures(filePaths)
        const sigChecked = [...sigResults.values()].filter(Boolean).length
        const sigTotal = [...sigResults.values()].filter(v => v === false).length + sigChecked
        if (sigTotal > 0) {
          console.log(`  🔐 Batch signature check: ${sigChecked}/${sigTotal} valid (${(sigChecked/sigTotal*100).toFixed(0)}%)`)
        }
      }

      // ── PARALLEL: Process files concurrently via worker pool ──
      if (filePaths.length > 0) {
        const scanResults = await runParallel(filePaths, async (filePath) => {
          let hr = heuristicFileScan(filePath)
          let riskScore = hr?.riskScore || 0
          const shadowHits = hr?.shadowRuleHits

          // ── Shadow-mode routing ──
          // If file has shadow rule hits but low real risk, route to shadowFindings silently.
          // User never sees these — telemetry only for admin review.
          if (shadowHits && shadowHits.length > 0 && riskScore < 20) {
            const ext2 = path.extname(filePath).toLowerCase()
            // Extract rule name from first shadow hit for server-side grouping
            const ruleName = shadowHits[0]?.match(/\[([^\]]+)\]/)?.[1] || 'unknown'
            let shadowSha256: string | undefined
            if (ext2 === '.exe' || ext2 === '.dll' || ext2 === '.sys') {
              let fd2: number | undefined
              try {
                const h = crypto.createHash('sha256')
                fd2 = fs.openSync(filePath, 'r')
                const st = fs.statSync(filePath)
                const buf = Buffer.alloc(Math.min(st.size, 50 * 1024 * 1024))
                fs.readSync(fd2, buf, 0, buf.length, 0)
                h.update(buf)
                shadowSha256 = h.digest('hex')
              } catch { /* sha256 optional */ }
              finally { if (fd2 !== undefined) { try { fs.closeSync(fd2) } catch { /* best effort */ } } }
            }
            ctx.shadowFindings.push({
              path: filePath,
              fileName: path.basename(filePath),
              type: 'file',
              risk: 'low',
              matches: shadowHits.slice(0, 5),
              size: 0,
              modifiedAt: new Date().toISOString(),
              ruleName,
              sha256: shadowSha256,
            })
            // Only return if no real risk — otherwise continue to also report as real finding
            if (riskScore <= 0) return null
          }

          // Location bonus
          const fpLower = filePath.toLowerCase()
          if (fpLower.includes('downloads') || fpLower.includes('download') || fpLower.includes('desktop') || fpLower.includes('temp') || fpLower.includes('загрузки')) {
            riskScore += 10
          }
          // Fuzzy hash for .exe/.dll
          const ext = path.extname(filePath).toLowerCase()
          if ((ext === '.exe' || ext === '.dll') && riskScore < 40) {
            const fuzzyMatch = fuzzyMatchFile(filePath, 25)
            if (fuzzyMatch && fuzzyMatch.matched) {
              riskScore = Math.max(riskScore, 60)
              if (!hr) hr = { riskScore: 60, suspicions: [] }
              hr.suspicions.push(`fuzzy-hash:matched (distance=${fuzzyMatch.distance})`)
            }
          }
          // ── Persistent escalation bonus ──
          if (ctx.escalationBonus > 0 && riskScore > 10) {
            riskScore += ctx.escalationBonus
            if (!hr) hr = { riskScore: ctx.escalationBonus, suspicions: [] }
            hr.suspicions.push(`persistent-profile:escalated +${ctx.escalationBonus} (repeated suspicious activity)`)
          }
          if (hr && riskScore > 20) {
            const risk = riskScore > 80 ? 'high' : riskScore > 50 ? 'medium' : 'low'

            // ── Compute hashes for ALL suspicious files ──
            // partialHash (first 64KB) is FAST — read from safe-files-db
            // sha256 (full file) is SLOW — only for high-risk binaries
            let sha256Hash: string | undefined
            let partialHash: string | undefined
            let fileSize = 0
            try {
              // Compute partial hash for EVERY result — fast first-64KB read
              const stat2 = fs.statSync(filePath)
              fileSize = stat2.size
              const partialBuf = Buffer.alloc(Math.min(stat2.size, 64 * 1024))
              let fd: number | undefined
              try {
                fd = fs.openSync(filePath, 'r')
                fs.readSync(fd, partialBuf, 0, partialBuf.length, 0)
              } finally {
                if (fd !== undefined) { try { fs.closeSync(fd) } catch { /* best effort */ } }
              }
              partialHash = crypto.createHash('sha256').update(partialBuf).digest('hex')

              // Full sha256 only for high-risk binaries (expensive)
              if (risk === 'high' && (ext === '.exe' || ext === '.dll' || ext === '.sys')) {
                const h = crypto.createHash('sha256')
                const fullBuf = Buffer.alloc(Math.min(stat2.size, 50 * 1024 * 1024))
                let fd2: number | undefined
                try {
                  fd2 = fs.openSync(filePath, 'r')
                  fs.readSync(fd2, fullBuf, 0, fullBuf.length, 0)
                } finally {
                  if (fd2 !== undefined) { try { fs.closeSync(fd2) } catch { /* best effort */ } }
                }
                h.update(fullBuf)
                sha256Hash = h.digest('hex')
              }
            } catch { /* hash optional */ }

            return {
              path: filePath,
              fileName: path.basename(filePath),
              type: 'file' as const,
              risk,
              matches: hr.suspicions.slice(0, 5),
              size: fileSize,
              modifiedAt: new Date().toISOString(),
              sha256: sha256Hash,
              partialHash,
              hasValidSignature: hr.hasValidSignature,
            } satisfies ScanResult
          }
          return null
        }, { concurrency: 4, signal: ctx.abortController?.signal })

        // Filter nulls and add to results
        for (const r of scanResults) {
          if (r) results.push(r)
        }
        filesScanned += filePaths.length
      }
    } catch (_e) { /* skip */ }
  }

  if (aborted()) return { results, filesScanned }

  // Phase 3-5: parallel execution (registry + prefetch + network are independent)
  await sendProgress(win, { phase: 'scanning', currentDir: 'Parallel: registry + prefetch + network...', filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 4 })
  const [regResults, prefResults, netResults] = await Promise.all([
    Promise.resolve(safeCall('scanRegistryDeepV2', () => scanRegistryDeepV2())),
    Promise.resolve(safeCall('scanPrefetchV2', () => scanPrefetchV2())),
    Promise.resolve(safeCall('scanNetstatV2', () => scanNetstatV2())),
  ])
  results.push(...regResults, ...prefResults, ...netResults)

  await sendProgress(win, { phase: 'scanning', currentDir: 'Parallel: exec + memory + behavior...', filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 6 })
  results.push(...safeCall('scanMasqueradingProcesses', () => scanMasqueradingProcesses()))

  if (aborted()) return { results, filesScanned }

  // Phase 5b — game integrity + modules + handles
  await sendProgress(win, { phase: 'scanning', currentDir: 'Game integrity...', filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 6 })
  results.push(...safeCall('scanGameIntegrity', () => scanGameIntegrity()))
  results.push(...safeCall('scanGameModules', () => scanGameModules()))
  results.push(...safeCall('scanOpenHandles', () => scanOpenHandles()))

  if (aborted()) return { results, filesScanned }

  // Phase 5c — named pipes + WMI + AMSI/ETW patch + ETW kernel monitor + BYOVD driver scan
  await sendProgress(win, { phase: 'scanning', currentDir: 'IPC & persistence...', filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 6 })
  results.push(...safeCall('scanNamedPipes', () => scanNamedPipes()))
  results.push(...safeCall('scanWmiPersistence', () => scanWmiPersistence()))
  // ETW/WMI kernel-level monitoring
  results.push(...safeCall('runEtwScan', () => runEtwScan()))
  // APC Injection + Atom Bombing detection (thread analysis + atom tables)
  results.push(...safeCall('runApcScan', () => runApcScan()))
  // BYOVD — scan for known vulnerable kernel drivers (gdrv.sys, RTCore64.sys, Capcom.sys, etc.)
  results.push(...safeCall('scanByovd', () => scanByovd()))

  // AMSI/ETW patch detection — abort checked BEFORE expensive PowerShell call (10s timeout)
  if (aborted()) return { results, filesScanned }
  try {
    const psOut = execSync(
      `powershell -Command "Get-Process | Where-Object { $_.Modules } | Select-Object Name, Id, @{N='Mods';E={$_.Modules | Select -Expand ModuleName}} | ConvertTo-Json -Depth 3"`,
      { encoding: 'utf-8', timeout: 10000 },
    )
    const processes = parsePsJson<{ Name?: string; Id?: number; Mods?: string[] }>(psOut)
    for (const proc of processes) {
        if (aborted()) break
        const mods: string[] = proc.Mods || []
        const patchResult = await scanProcessForAmsiEtw(Number(proc.Id), (proc.Name || '').toLowerCase())
        if (patchResult && (patchResult.amsiPatched || patchResult.etwPatched) && patchResult.riskScore > 20) {
          results.push({
            path: `process:${proc.Name} (PID: ${proc.Id})`,
            fileName: `${proc.Name} — AMSI/ETW patch detected`,
            type: 'process',
            risk: 'high',
            matches: ['AMSI patching / ETW evasion detected', 'Process bypassing AMSI scanning'],
            size: 0,
            modifiedAt: new Date().toISOString(),
          })
        }
        // Behavior profile
        try {
          const profile = buildBehaviorProfile(Number(proc.Id), (proc.Name || '').toLowerCase(), mods)
          const pr = profileToScanResult(profile)
          if (pr) results.push(pr)
        } catch (_e) { /* skip */ }
        // RWX memory scan
        try {
          const rwxResult = scanRwxAndThreads(Number(proc.Id), (proc.Name || '').toLowerCase())
          if (rwxResult) {
            const rwxResult2 = rwxResultToScanResult(rwxResult)
            if (rwxResult2) results.push(rwxResult2)
          }
        } catch (_e) { /* skip */ }
        // Disk vs memory analysis
        try {
          const dvmResult = scanDiskVsMemory(Number(proc.Id), (proc.Name || '').toLowerCase())
          if (dvmResult) {
            const dvmResult2 = dvmResultToScanResult(dvmResult)
            if (dvmResult2) results.push(dvmResult2)
          }
        } catch (_e) { /* skip */ }
      }
  } catch (_e) { /* PowerShell AMSI scan failed */ }

  if (aborted()) return { results, filesScanned }

  // Phase 6 — DMA + scheduled tasks + IOMMU
  await sendProgress(win, { phase: 'scanning', currentDir: 'DMA devices + IOMMU...', filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 8 })
  results.push(...safeCall('scanDmaDevices', () => scanDmaDevices()))
  results.push(...safeCall('checkIommuStatus', () => checkIommuStatus()))
  await sendProgress(win, { phase: 'scanning', currentDir: 'Scheduled tasks...', filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 8 })
  results.push(...safeCall('scanScheduledTasks', () => scanScheduledTasks()))

  if (aborted()) return { results, filesScanned }

  // Phase 7 — registry cheat scan
  await sendProgress(win, { phase: 'scanning', currentDir: 'Registry cheat scan...', filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 9 })
  results.push(...safeCall('scanRegistryForCheats', () => scanRegistryForCheats()))

  if (aborted()) return { results, filesScanned }

  // Phase 8 — browser history
  await sendProgress(win, { phase: 'analyzing', currentDir: 'Browser history...', filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 10 })
  try {
    const bh = await scanBrowserHistory(ALL_CHEAT_KEYWORDS)
    results.push(...safeSpread('scanBrowserHistory', bh))
  } catch (err) {
    console.error('[scan] scanBrowserHistory crashed:', (err as Error).message || err)
  }

  if (aborted()) return { results, filesScanned }

  // Phase 9 — Forensic artifact scan (Prefetch, Amcache, BAM, UserAssist, EventLogs...)
  await sendProgress(win, { phase: 'scanning', currentDir: 'Forensic artifact scan...', filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 11 })
  results.push(...safeCall('runForensicScan', () => runForensicScan()))

  if (aborted()) return { results, filesScanned }

  // Phase 10 — Anti-forensic scan (log clearing, cleaning tools, tampering)
  await sendProgress(win, { phase: 'scanning', currentDir: 'Anti-forensic integrity check...', filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 12 })
  results.push(...safeCall('runAntiForensicScan', () => runAntiForensicScan()))

  if (aborted()) return { results, filesScanned }

  // Phase 11 — Enhanced PC cleaning detection (USN journal, timestomping, ShellBags, MRU)
  await sendProgress(win, { phase: 'scanning', currentDir: 'PC cleaning detection...', filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 13 })
  results.push(...safeCall('runPcCleanerScan', () => runPcCleanerScan()))

  await sendProgress(win, { phase: 'done', currentDir: '', filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 13 })
  return { results, filesScanned }
}

// ═══════════════════════════════════════════════════
// QUICK SCAN — processes + prefetch + registry + browser
// ═══════════════════════════════════════════════════

async function runQuickScan(win: BrowserWindow | null): Promise<{ results: ScanResult[]; filesScanned: number }> {
  const results: ScanResult[] = []
  let filesScanned = 0
  const signal = ctx.abortController?.signal
  const aborted = () => signal?.aborted ?? false

  clearFindingDedup()

  // ── Phase 0: Anti-Tamper ──
  results.push(...safeCall('runAntiTamperScan', () => runAntiTamperScan()))
  if (aborted()) return { results, filesScanned }

  // NOTE: sigCache intentionally NOT cleared — persists between scans.
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
  } catch (err) {
    console.error('[scan] scanBrowserHistory crashed:', (err as Error).message || err)
  }

  await sendProgress(win, { phase: 'done', currentDir: '', filesFound: results.length, filesScanned: results.length, totalDirs: 6, dirsDone: 6 })
  return { results, filesScanned: results.length }
}

// ═══════════════════════════════════════════════════
// MAIN IPC HANDLER
// ═══════════════════════════════════════════════════

// ═══════════════════════════════════════════════════
// CLEANER SCAN — PC cleaning detection + anti-forensic + forensic traces
// ═══════════════════════════════════════════════════

async function runCleanerScan(win: BrowserWindow | null): Promise<{ results: ScanResult[]; filesScanned: number }> {
  const results: ScanResult[] = []
  const signal = ctx.abortController?.signal
  const aborted = () => signal?.aborted ?? false

  clearFindingDedup()

  // ── Phase 0: Anti-Tamper ──
  results.push(...safeCall('runAntiTamperScan', () => runAntiTamperScan()))
  if (aborted()) return { results, filesScanned: 0 }

  // NOTE: sigCache intentionally NOT cleared — persists between scans.
  await sendProgress(win, { phase: 'scanning', currentDir: 'PC cleaning detection...', filesFound: results.length, filesScanned: 0, totalDirs: 4, dirsDone: 1 })
  results.push(...safeCall('runPcCleanerScan', () => runPcCleanerScan()))

  if (aborted()) return { results, filesScanned: 0 }

  await sendProgress(win, { phase: 'scanning', currentDir: 'Anti-forensic integrity check...', filesFound: results.length, filesScanned: 0, totalDirs: 4, dirsDone: 2 })
  results.push(...safeCall('runAntiForensicScan', () => runAntiForensicScan()))

  if (aborted()) return { results, filesScanned: 0 }

  await sendProgress(win, { phase: 'scanning', currentDir: 'Forensic artifact scan...', filesFound: results.length, filesScanned: 0, totalDirs: 4, dirsDone: 3 })
  results.push(...safeCall('runForensicScan', () => runForensicScan()))

  if (aborted()) return { results, filesScanned: 0 }

  // DMA + IOMMU check (HWID spoofing often involves disabling IOMMU)
  await sendProgress(win, { phase: 'scanning', currentDir: 'IOMMU / DMA integrity...', filesFound: results.length, filesScanned: 0, totalDirs: 4, dirsDone: 4 })
  results.push(...safeCall('checkIommuStatus', () => checkIommuStatus()))

  await sendProgress(win, { phase: 'done', currentDir: '', filesFound: results.length, filesScanned: results.length, totalDirs: 4, dirsDone: 4 })
  return { results, filesScanned: 0 } // filesScanned = 0 (not a file-walking scan)
}

export { startCloudSync, stopCloudSync, fetchCheatHashes } from './cloud-sync'
export { startTelemetryQueue, stopTelemetryQueue } from './telemetry-queue'

interface ScanOptions {
  token_id?: number
  tokenId?: number
  pc_username?: string
  pcUsername?: string
}

// ── Initialize safe-files DB with community whitelist ──
// Load local DB first, then overlay community-verified safe files from server.
// This ensures ALL devices immediately know which files are safe.
export async function initSafeFilesDb(): Promise<void> {
  loadSafeFilesDb()
  try {
    const count = await syncSafeFilesFromServer()
    console.log(`  📁 Safe files DB ready: ${getSafeFilesCount()} entries (${count} new from server)`)
  } catch (_e) { /* server sync optional */ }
}

/** Initialize telemetry queue for reliable result delivery */
export function initTelemetry(): void {
  startTelemetryQueue()
  console.log('  📤 Telemetry queue started')
}

export function registerScanHandlers() {
  // ── Cancel active scan ──
  ipcMain.handle('cancel-scan', async () => {
    if (ctx.abortController) {
      ctx.abortController.abort()
      console.log('  Scan cancelled by user')
      return { success: true }
    }
    return { success: false, error: 'No active scan' }
  })

  ipcMain.handle('start-scan', async (event, mode: ScanMode, options?: ScanOptions) => {
    const win = BrowserWindow.fromWebContents(event.sender)
    const tokenId = options?.token_id ?? options?.tokenId ?? 0
    const pcUsername = options?.pc_username ?? options?.pcUsername ?? 'unknown'

    // ── Persistent profile escalation ──
    const escalationBonus = getEscalationBonus()
    const profile = getProfileSummary()
    if (escalationBonus > 0) {
      console.log(`  📈 Profile ESCALATED: ${profile.consistencyPercent}% consistency over last scans — adding +${escalationBonus} to all findings`)
    }
    ctx.escalationBonus = escalationBonus

    // Internal state cleanup — preserves expensive caches (sigCache, peHeaderCache)
    ctx.resetScan()

    try {
      const startTime = Date.now()

      let result: { results: ScanResult[]; filesScanned: number }

      switch (mode) {
        case 'full':
          result = await runFullScan(win)
          break
        case 'quick':
          result = await runQuickScan(win)
          break
        case 'dma':
          result = await runDmaScan(win)
          break
        case 'cleaner':
          result = await runCleanerScan(win)
          break
        default:
          result = { results: [], filesScanned: 0 }
      }

      // Ensure results is always an array
      if (!Array.isArray(result.results)) {
        result.results = []
      }

      await sendProgress(win, {
        phase: 'done',
        currentDir: '',
        filesFound: result.results.length,
        filesScanned: result.filesScanned,
        totalDirs: 1,
        dirsDone: 1,
      })

      const summary = {
        totalScanned: result.filesScanned,
        suspiciousFiles: result.results.length,
        highRiskCount: result.results.filter(r => r.risk === 'high').length,
        scanTimeMs: Date.now() - startTime,
      }

      // ── Filter noise BEFORE returning to UI ──
      // ALL results go to the pipeline for server-side analysis.
      // Only filtered results go to the UI (user sees real threats only).
      const filteredResults = filterNoiseFindings(result.results)
      const filteredCount = result.results.length - filteredResults.length
      if (filteredCount > 0) {
        console.log(`  🔇 Filtered ${filteredCount} noise findings (${result.results.length} → ${filteredResults.length} shown to user)`)
      }

      // ── Post-scan pipeline ──
      // IMPORTANT: Pipeline receives ALL raw results for comprehensive server-side analysis.
      // Filtering only affects what the USER sees in the UI.
      await runPostScanPipeline(result.results, summary, {
        tokenId,
        pcUsername,
        mode,
        startTime,
      })

      return { results: filteredResults, summary } satisfies ScanResponse
    } catch (err) {
      console.error(`Scan error (${mode}):`, err)
      return {
        results: [],
        summary: { totalScanned: 0, suspiciousFiles: 0, highRiskCount: 0, scanTimeMs: 0 },
      } satisfies ScanResponse
    }
  })
}
