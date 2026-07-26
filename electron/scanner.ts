import { ipcMain, BrowserWindow } from 'electron'
import crypto from 'crypto'
import fs from 'fs'
import http from 'http'
import https from 'https'
import path from 'path'
import { execSync } from 'child_process'

import { getApiBase, getApiEndpoint } from './config'
import { fetchCheatHashes, startCloudSync, stopCloudSync } from './cloud-sync'
import { CHEAT_SOFTWARE_NAMES, EXTENDED_CHEAT_KEYWORDS, EXTENDED_SCAN_PATHS } from './constants'

import {
  KNOWN_CHEAT_HASHES,
  mergeCheatHashes,
  getScanPaths,
} from './cheats-db'

import {
  evaluateYara,
  isTrustedPath,
  analyzePeHeaders,
  analyzeSectionEntropy,
} from './cheat-rules'

import {
  checkAutoRules,
  learnFromFile,
} from './auto-yara'

import {
  dumpAndAnalyze,
  dumpProcessMemory,
} from './memory-dump'

import {
  analyzeApiHashingStatic,
  analyzeApiHashingInDump,
} from './api-hashing'

import {
  scanProcessForAmsiEtw,
} from './etw-amsi-patch'

import {
  buildBehaviorProfile,
  profileToScanResult,
} from './behavior-profile'

import {
  scanRwxAndThreads,
  rwxResultToScanResult,
} from './rwx-scanner'

import {
  scanDiskVsMemory,
  dvmResultToScanResult,
} from './disk-vs-memory'

// ── Shared types, utilities, heuristics ──

import {
  ScanResult,
  ScanProgress,
  ScanResponse,
  ScanMode,
  sendProgress,
  yieldToEventLoop,
  clearFindingDedup,
  parsePsJson,
  ctx,
} from './types'

import {
  heuristicFileScan,
  calculateEntropy,
  SUSPICIOUS_CATEGORIES,
  SUSPICIOUS_PATTERNS,
  ALL_CHEAT_KEYWORDS,
  checkDigitalSignature,
  scanStrings,
  matchKnownCheat,
} from './heuristic'

// ── Scan mode modules ──

import { runFileScan, walkDirAsync, scanForCheatFiles } from './modes/files'
import { runProcessScan, scanRunningProcessesV2, scanNamedPipes, scanWmiPersistence } from './modes/processes'
import { scanGameIntegrity, scanGameModules, scanMasqueradingProcesses, scanOpenHandles, runGameScan } from './modes/games'
import { runNetworkScan, scanNetstatV2 } from './modes/network'
import { scanRegistryDeepV2, scanPrefetchV2, scanRegistryForCheats } from './modes/registry'
import { scanBrowserHistory } from './modes/browser'
import { runDmaScan, scanDmaDevices, scanDmaRegistry, scanScheduledTasks, queryPnpDevices } from './modes/dma'

// ═══════════════════════════════════════════════════
// SAFE SPREAD UTILITY
// ═══════════════════════════════════════════════════

function safeSpread<T>(label: string, value: T[] | null | undefined): T[] {
  if (!Array.isArray(value)) {
    console.error(`[safeSpread] ${label} — expected array, got:`, typeof value, value)
    return []
  }
  return [...value]
}

// ═══════════════════════════════════════════════════
// CHEAT SCAN
// ═══════════════════════════════════════════════════

async function runCheatScan(win: BrowserWindow | null): Promise<{ results: ScanResult[]; filesScanned: number }> {
  const results: ScanResult[] = []
  const cheatNames = Object.keys(CHEAT_SOFTWARE_NAMES)
  let filesScanned = 0

  for (let i = 0; i < cheatNames.length; i++) {
    const cheatName = cheatNames[i]
    const keywords = CHEAT_SOFTWARE_NAMES[cheatName]

    await sendProgress(win, { phase: 'scanning', currentDir: `Searching for ${cheatName}...`, filesFound: results.length, filesScanned, totalDirs: cheatNames.length + 2, dirsDone: i + 1 })

    const fileResults = scanForCheatFiles(cheatName, keywords)
    results.push(...fileResults)
    filesScanned += fileResults.length
  }

  const cheatKw = (Object.values(CHEAT_SOFTWARE_NAMES).flat() as string[])
  const browserResults = await scanBrowserHistory(cheatKw)
  results.push(...browserResults)

  await sendProgress(win, { phase: 'analyzing', currentDir: 'Checking registry...', filesFound: results.length, filesScanned, totalDirs: cheatNames.length + 2, dirsDone: cheatNames.length + 1 })
  const registryResults = scanRegistryForCheats()
  results.push(...registryResults)

  return { results, filesScanned: results.length }
}

// ═══════════════════════════════════════════════════
// EXTENDED SCAN
// ═══════════════════════════════════════════════════

async function runExtendedScan(win: BrowserWindow | null): Promise<{ results: ScanResult[]; filesScanned: number }> {
  const results: ScanResult[] = []
  let filesScanned = 0

  clearFindingDedup()
  ctx.sigCache.clear()
  await sendProgress(win, { phase: 'scanning', currentDir: 'Advanced process scanning...', filesFound: results.length, filesScanned, totalDirs: 9, dirsDone: 1 })
  results.push(...safeSpread('scanRunningProcessesV2', scanRunningProcessesV2()))

  // Phase 2 — heuristic file scan
  await sendProgress(win, { phase: 'scanning', currentDir: `Heuristic file scan (${EXTENDED_SCAN_PATHS.length} directories)...`, filesFound: results.length, filesScanned, totalDirs: 9, dirsDone: 2 })
  for (const dir of EXTENDED_SCAN_PATHS) {
    await sendProgress(win, { phase: 'scanning', currentDir: dir, filesFound: results.length, filesScanned, totalDirs: 9, dirsDone: 2 })
    try {
      for await (const filePath of walkDirAsync(dir)) {
        filesScanned++
        const hr = heuristicFileScan(filePath)
        if (hr && hr.riskScore > 30) {
          results.push({
            path: filePath,
            fileName: path.basename(filePath),
            type: 'file',
            risk: hr.riskScore > 80 ? 'high' : hr.riskScore > 50 ? 'medium' : 'low',
            matches: hr.suspicions.slice(0, 5),
            size: 0,
            modifiedAt: new Date().toISOString(),
          })
        }
        await yieldToEventLoop()
      }
    } catch (_e) { /* skip */ }
  }

  // Phase 3 — registry deep scan
  await sendProgress(win, { phase: 'scanning', currentDir: 'Registry deep scan...', filesFound: results.length, filesScanned, totalDirs: 9, dirsDone: 3 })
  results.push(...safeSpread('scanRegistryDeepV2', scanRegistryDeepV2()))

  // Phase 4 — prefetch
  await sendProgress(win, { phase: 'scanning', currentDir: 'Prefetch analysis...', filesFound: results.length, filesScanned, totalDirs: 9, dirsDone: 4 })
  results.push(...safeSpread('scanPrefetchV2', scanPrefetchV2()))

  // Phase 5 — network + system integration
  await sendProgress(win, { phase: 'scanning', currentDir: 'Network connections...', filesFound: results.length, filesScanned, totalDirs: 9, dirsDone: 5 })
  results.push(...safeSpread('scanNetstatV2', scanNetstatV2()))

  // Phase 5a — masquerading processes
  await sendProgress(win, { phase: 'scanning', currentDir: 'Masquerading processes...', filesFound: results.length, filesScanned, totalDirs: 9, dirsDone: 5 })
  results.push(...safeSpread('scanMasqueradingProcesses', scanMasqueradingProcesses()))

  // Phase 5b — game integrity + modules + handles
  await sendProgress(win, { phase: 'scanning', currentDir: 'Game integrity...', filesFound: results.length, filesScanned, totalDirs: 9, dirsDone: 5 })
  results.push(...safeSpread('scanGameIntegrity', scanGameIntegrity()))
  results.push(...safeSpread('scanGameModules', scanGameModules()))
  results.push(...safeSpread('scanOpenHandles', scanOpenHandles()))

  // Phase 5c — named pipes + WMI + AMSI/ETW patch
  await sendProgress(win, { phase: 'scanning', currentDir: 'IPC & persistence...', filesFound: results.length, filesScanned, totalDirs: 9, dirsDone: 5 })
  results.push(...safeSpread('scanNamedPipes', scanNamedPipes()))
  results.push(...safeSpread('scanWmiPersistence', scanWmiPersistence()))

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

  // Phase 6 — DMA + scheduled tasks
  await sendProgress(win, { phase: 'scanning', currentDir: 'DMA devices...', filesFound: results.length, filesScanned, totalDirs: 9, dirsDone: 6 })
  results.push(...safeSpread('scanDmaDevices', scanDmaDevices()))
  await sendProgress(win, { phase: 'scanning', currentDir: 'Scheduled tasks...', filesFound: results.length, filesScanned, totalDirs: 9, dirsDone: 6 })
  results.push(...safeSpread('scanScheduledTasks', scanScheduledTasks()))

  // Phase 7 — registry cheat scan
  await sendProgress(win, { phase: 'scanning', currentDir: 'Registry cheat scan...', filesFound: results.length, filesScanned, totalDirs: 9, dirsDone: 7 })
  results.push(...safeSpread('scanRegistryForCheats', scanRegistryForCheats()))

  // Phase 8 — browser history
  await sendProgress(win, { phase: 'analyzing', currentDir: 'Browser history...', filesFound: results.length, filesScanned, totalDirs: 9, dirsDone: 8 })
  results.push(...safeSpread('scanBrowserHistory', await scanBrowserHistory(EXTENDED_CHEAT_KEYWORDS)))

  await sendProgress(win, { phase: 'done', currentDir: '', filesFound: results.length, filesScanned, totalDirs: 9, dirsDone: 9 })
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
        case 'files':
          result = await runFileScan(win)
          break
        case 'processes':
          result = await runProcessScan(win)
          break
        case 'cheats':
          result = await runCheatScan(win)
          break
        case 'dma':
          result = await runDmaScan(win)
          break
        case 'extended':
          result = await runExtendedScan(win)
          break
        case 'network':
          result = await runNetworkScan(win)
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
