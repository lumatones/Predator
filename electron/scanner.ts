import { ipcMain, BrowserWindow } from 'electron'
import crypto from 'crypto'
import fs from 'fs'
import http from 'http'
import https from 'https'
import path from 'path'
import { execSync } from 'child_process'

import { getApiEndpoint } from './config'
import { startCloudSync, stopCloudSync, fetchCheatHashes } from './cloud-sync'
import { EXTENDED_CHEAT_KEYWORDS, EXTENDED_SCAN_PATHS, QUICK_CHEAT_KEYWORDS } from './constants'

import { scanProcessForAmsiEtw } from './etw-amsi-patch'
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

import { heuristicFileScan } from './heuristic'
import { fuzzyMatchFile } from './fuzzy-hash'
import { recordSession } from './persistent-profile'

import { walkDirAsync } from './modes/files'
import { scanRunningProcessesV2, scanNamedPipes, scanWmiPersistence } from './modes/processes'
import { scanGameIntegrity, scanGameModules, scanMasqueradingProcesses, scanOpenHandles } from './modes/games'
import { scanNetstatV2 } from './modes/network'
import { scanRegistryDeepV2, scanPrefetchV2, scanRegistryForCheats } from './modes/registry'
import { scanBrowserHistory } from './modes/browser'
import { runDmaScan, scanDmaDevices, scanScheduledTasks, checkIommuStatus } from './modes/dma'
import { safeSpread } from './utils/safe-spread'
import { runEtwScan } from './etw-provider'
import { runForensicScan } from './forensic-traces'
import { runAntiForensicScan } from './anti-forensic'

// ═══════════════════════════════════════════════════
// FULL SCAN (was extended) — 9-phase deep scan
// ═══════════════════════════════════════════════════

async function runFullScan(win: BrowserWindow | null): Promise<{ results: ScanResult[]; filesScanned: number }> {
  const results: ScanResult[] = []
  let filesScanned = 0

  clearFindingDedup()
  ctx.sigCache.clear()
  await sendProgress(win, { phase: 'scanning', currentDir: 'Advanced process scanning...', filesFound: results.length, filesScanned, totalDirs: 9, dirsDone: 1 })
  results.push(...safeSpread('scanRunningProcessesV2', scanRunningProcessesV2()))

  // Phase 2 — heuristic file scan (with incremental + pre-filter + fuzzy hash)
  await sendProgress(win, { phase: 'scanning', currentDir: `Heuristic file scan (${EXTENDED_SCAN_PATHS.length} directories)...`, filesFound: results.length, filesScanned, totalDirs: 9, dirsDone: 2 })
  for (const dir of EXTENDED_SCAN_PATHS) {
    await sendProgress(win, { phase: 'scanning', currentDir: dir, filesFound: results.length, filesScanned, totalDirs: 9, dirsDone: 2 })
    try {
      for await (const filePath of walkDirAsync(dir)) {
        filesScanned++
        // Always run heuristic scan (expensive but thorough)
        let hr = heuristicFileScan(filePath)
        let riskScore = hr?.riskScore || 0
        // Location bonus — files in Downloads/Desktop/Temp are extra suspicious (BEFORE threshold check!)
        const fpLower = filePath.toLowerCase()
        if (fpLower.includes('downloads') || fpLower.includes('download') || fpLower.includes('desktop') || fpLower.includes('temp') || fpLower.includes('загрузки')) {
          riskScore += 10
        }
        // Fuzzy hash check for .exe/.dll (catches polymorphic variants)
        const ext = path.extname(filePath).toLowerCase()
        if ((ext === '.exe' || ext === '.dll') && riskScore < 40) {
          const fuzzyMatch = fuzzyMatchFile(filePath, 25)
          if (fuzzyMatch && fuzzyMatch.matched) {
            riskScore = Math.max(riskScore, 60)
            if (!hr) hr = { riskScore: 60, suspicions: [] }
            hr.suspicions.push(`fuzzy-hash:matched (distance=${fuzzyMatch.distance})`)
          }
        }
        if (hr && riskScore > 20) {
          results.push({
            path: filePath,
            fileName: path.basename(filePath),
            type: 'file',
            risk: riskScore > 80 ? 'high' : riskScore > 50 ? 'medium' : 'low',
            matches: hr.suspicions.slice(0, 5),
            size: 0,
            modifiedAt: new Date().toISOString(),
          })
        }
        await yieldToEventLoop()
      }
    } catch (_e) { /* skip */ }
  }

  // Phase 3-5: parallel execution (registry + prefetch + network are independent)
  await sendProgress(win, { phase: 'scanning', currentDir: 'Parallel: registry + prefetch + network...', filesFound: results.length, filesScanned, totalDirs: 9, dirsDone: 3 })
  const [regResults, prefResults, netResults] = await Promise.all([
    Promise.resolve(safeSpread('scanRegistryDeepV2', scanRegistryDeepV2())),
    Promise.resolve(safeSpread('scanPrefetchV2', scanPrefetchV2())),
    Promise.resolve(safeSpread('scanNetstatV2', scanNetstatV2())),
  ])
  results.push(...regResults, ...prefResults, ...netResults)

  await sendProgress(win, { phase: 'scanning', currentDir: 'Parallel: exec + memory + behavior...', filesFound: results.length, filesScanned, totalDirs: 9, dirsDone: 5 })
  results.push(...safeSpread('scanMasqueradingProcesses', scanMasqueradingProcesses()))

  // Phase 5b — game integrity + modules + handles
  await sendProgress(win, { phase: 'scanning', currentDir: 'Game integrity...', filesFound: results.length, filesScanned, totalDirs: 9, dirsDone: 5 })
  results.push(...safeSpread('scanGameIntegrity', scanGameIntegrity()))
  results.push(...safeSpread('scanGameModules', scanGameModules()))
  results.push(...safeSpread('scanOpenHandles', scanOpenHandles()))

  // Phase 5c — named pipes + WMI + AMSI/ETW patch + ETW kernel monitor
  await sendProgress(win, { phase: 'scanning', currentDir: 'IPC & persistence...', filesFound: results.length, filesScanned, totalDirs: 9, dirsDone: 5 })
  results.push(...safeSpread('scanNamedPipes', scanNamedPipes()))
  results.push(...safeSpread('scanWmiPersistence', scanWmiPersistence()))
  // ETW/WMI kernel-level monitoring
  results.push(...safeSpread('runEtwScan', runEtwScan()))

  // AMSI/ETW patch detection
  try {
    const psOut = execSync(
      `powershell -Command "Get-Process | Where-Object { $_.Modules } | Select-Object Name, Id, @{N='Mods';E={$_.Modules | Select -Expand ModuleName}} | ConvertTo-Json -Depth 3"`,
      { encoding: 'utf-8', timeout: 10000 },
    )
    const processes = parsePsJson<{ Name?: string; Id?: number; Mods?: string[] }>(psOut)
    for (const proc of processes) {
        const mods: string[] = proc.Mods || []
        const skipAmsi = await scanProcessForAmsiEtw(Number(proc.Id), (proc.Name || '').toLowerCase())
        if (skipAmsi) {
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

  // Phase 6 — DMA + scheduled tasks + IOMMU
  await sendProgress(win, { phase: 'scanning', currentDir: 'DMA devices + IOMMU...', filesFound: results.length, filesScanned, totalDirs: 12, dirsDone: 6 })
  results.push(...safeSpread('scanDmaDevices', scanDmaDevices()))
  results.push(...safeSpread('checkIommuStatus', checkIommuStatus()))
  await sendProgress(win, { phase: 'scanning', currentDir: 'Scheduled tasks...', filesFound: results.length, filesScanned, totalDirs: 9, dirsDone: 6 })
  results.push(...safeSpread('scanScheduledTasks', scanScheduledTasks()))

  // Phase 7 — registry cheat scan
  await sendProgress(win, { phase: 'scanning', currentDir: 'Registry cheat scan...', filesFound: results.length, filesScanned, totalDirs: 9, dirsDone: 7 })
  results.push(...safeSpread('scanRegistryForCheats', scanRegistryForCheats()))

  // Phase 8 — browser history
  await sendProgress(win, { phase: 'analyzing', currentDir: 'Browser history...', filesFound: results.length, filesScanned, totalDirs: 9, dirsDone: 8 })
  results.push(...safeSpread('scanBrowserHistory', await scanBrowserHistory(EXTENDED_CHEAT_KEYWORDS)))

  // Phase 9 — Forensic artifact scan (Prefetch, Amcache, BAM, UserAssist, EventLogs...)
  await sendProgress(win, { phase: 'scanning', currentDir: 'Forensic artifact scan...', filesFound: results.length, filesScanned, totalDirs: 12, dirsDone: 9 })
  results.push(...safeSpread('runForensicScan', runForensicScan()))

  // Phase 10 — Anti-forensic scan (log clearing, cleaning tools, tampering)
  await sendProgress(win, { phase: 'scanning', currentDir: 'Anti-forensic integrity check...', filesFound: results.length, filesScanned, totalDirs: 12, dirsDone: 10 })
  results.push(...safeSpread('runAntiForensicScan', runAntiForensicScan()))

  await sendProgress(win, { phase: 'done', currentDir: '', filesFound: results.length, filesScanned, totalDirs: 12, dirsDone: 12 })
  return { results, filesScanned }
}

// ═══════════════════════════════════════════════════
// QUICK SCAN — processes + prefetch + registry + browser
// ═══════════════════════════════════════════════════

async function runQuickScan(win: BrowserWindow | null): Promise<{ results: ScanResult[]; filesScanned: number }> {
  const results: ScanResult[] = []
  let filesScanned = 0

  clearFindingDedup()
  ctx.sigCache.clear()

  await sendProgress(win, { phase: 'scanning', currentDir: 'Processes...', filesFound: results.length, filesScanned, totalDirs: 5, dirsDone: 1 })
  results.push(...safeSpread('scanRunningProcessesV2', scanRunningProcessesV2()))
  results.push(...safeSpread('scanMasqueradingProcesses', scanMasqueradingProcesses()))

  await sendProgress(win, { phase: 'scanning', currentDir: 'Prefetch...', filesFound: results.length, filesScanned, totalDirs: 5, dirsDone: 2 })
  results.push(...safeSpread('scanPrefetchV2', scanPrefetchV2()))

  await sendProgress(win, { phase: 'scanning', currentDir: 'Registry...', filesFound: results.length, filesScanned, totalDirs: 5, dirsDone: 3 })
  results.push(...safeSpread('scanRegistryDeepV2', scanRegistryDeepV2()))
  results.push(...safeSpread('scanRegistryForCheats', scanRegistryForCheats()))

  await sendProgress(win, { phase: 'scanning', currentDir: 'Pipes & persistence...', filesFound: results.length, filesScanned, totalDirs: 6, dirsDone: 4 })
  results.push(...safeSpread('scanNamedPipes', scanNamedPipes()))
  results.push(...safeSpread('scanWmiPersistence', scanWmiPersistence()))

  await sendProgress(win, { phase: 'scanning', currentDir: 'Network...', filesFound: results.length, filesScanned, totalDirs: 6, dirsDone: 5 })
  results.push(...safeSpread('scanNetstatV2', scanNetstatV2()))

  await sendProgress(win, { phase: 'scanning', currentDir: 'Browser history...', filesFound: results.length, filesScanned, totalDirs: 6, dirsDone: 6 })
  results.push(...safeSpread('scanBrowserHistory', await scanBrowserHistory(QUICK_CHEAT_KEYWORDS)))

  await sendProgress(win, { phase: 'done', currentDir: '', filesFound: results.length, filesScanned, totalDirs: 6, dirsDone: 6 })
  filesScanned = results.length
  return { results, filesScanned }
}

// ═══════════════════════════════════════════════════
// MAIN IPC HANDLER
// ═══════════════════════════════════════════════════

export { startCloudSync, stopCloudSync, fetchCheatHashes } from './cloud-sync'

interface ScanOptions {
  token_id?: number
  tokenId?: number
  pc_username?: string
  pcUsername?: string
}

export function registerScanHandlers() {
  ipcMain.handle('start-scan', async (event, mode: ScanMode, options?: ScanOptions) => {
    const win = BrowserWindow.fromWebContents(event.sender)
    const tokenId = options?.token_id ?? options?.tokenId ?? 0
    const pcUsername = options?.pc_username ?? options?.pcUsername ?? 'unknown'

    // Internal state cleanup
    ctx.clear()

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

      // Record session for persistent scoring
      try {
        recordSession({
          mode,
          scanTimeMs: summary.scanTimeMs,
          filesScanned: summary.totalScanned,
          highRiskCount: summary.highRiskCount,
          mediumRiskCount: result.results.filter(r => r.risk === 'medium').length,
          lowRiskCount: result.results.filter(r => r.risk === 'low').length,
          topFindings: result.results.filter(r => r.risk === 'high').slice(0, 5).map(r => r.fileName),
        })
      } catch { /* persistent scoring optional */ }

      // Submit shadow findings silently (never flags user — telemetry only)
      if (ctx.shadowFindings.length > 0) {
        try {
          const shadowPayload = {
            type: 'shadow-findings',
            token_id: tokenId,
            pc_username: pcUsername,
            findings: ctx.shadowFindings.map(f => ({
              path: f.path, fileName: f.fileName, type: f.type, matches: f.matches,
            })),
          }
          const shadowBody = JSON.stringify(shadowPayload)
          const { hostname, port, protocol } = getApiEndpoint()
          const shadowTransport = protocol === 'https:' ? https : http
          const shadowReq = shadowTransport.request({
            hostname, port,
            path: '/api/auth/submit-shadow',
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(shadowBody) },
          })
          shadowReq.write(shadowBody)
          shadowReq.end()
        } catch { /* shadow submission optional */ }
      }

      // Fire-and-forget cloud submission of top findings
      const highRisk = result.results.filter(r => r.risk === 'high').slice(0, 10)
      if (highRisk.length > 0) {
        const payload = {
          token_id: tokenId,
          pc_username: pcUsername,
          hashes: await Promise.all(highRisk.map(async (r) => {
            let sha256 = ''
            if (r.path && fs.existsSync(r.path)) {
              const hash = crypto.createHash('sha256')
              try {
                const stream = fs.createReadStream(r.path)
                for await (const chunk of stream) hash.update(chunk as Buffer)
                sha256 = hash.digest('hex')
              } catch { /* skip */ }
            }
          return {
            sha256: sha256 || r.matches.find(m => m.startsWith('sha256:'))?.replace('sha256:', '') || '',
            file_name: r.fileName,
            pc_username: pcUsername,
            file_size: r.size,
            risk_score: r.risk === 'high' ? 80 : r.risk === 'medium' ? 50 : 20,
          }
          })),
        }

        try {
          const body = JSON.stringify(payload)
          const { hostname, port, protocol } = getApiEndpoint()
          const transport = protocol === 'https:' ? https : http
          const req = transport.request({
            hostname,
            port,
            path: '/api/auth/submit-hashes',
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
          })
          req.write(body)
          req.end()
        } catch { /* cloud submission optional */ }
      }

      return { results: result.results, summary } satisfies ScanResponse
    } catch (err) {
      console.error(`Scan error (${mode}):`, err)
      return {
        results: [],
        summary: { totalScanned: 0, suspiciousFiles: 0, highRiskCount: 0, scanTimeMs: 0 },
      } satisfies ScanResponse
    }
  })
}
