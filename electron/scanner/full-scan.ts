/**
 * Predator — Full Scan (12 phases)
 *
 * Extracted from scanner.ts for modularity and testability.
 * Orchestrates the complete deep-scan pipeline.
 */

import crypto from 'crypto'
import type { Stats } from 'fs'
import fsp from 'fs/promises'
import path from 'path'
import { execPowerShellAsync } from '../utils/exec'
import { readFilePrefix } from '../utils/file-io'
import { BrowserWindow } from 'electron'

import { EXTENDED_SCAN_PATHS } from '../constants'
import { heuristicFileScan, batchCheckSignatures, ALL_CHEAT_KEYWORDS } from '../heuristic'
import { fuzzyMatchFile } from '../fuzzy-hash'
import { walkDirAsync } from '../modes/files'
import { scanRunningProcessesV2, scanNamedPipes, scanWmiPersistence, scanBehavioralMasquerading } from '../modes/processes'
import { scanGameIntegrity, scanGameModules, scanMasqueradingProcesses, scanOpenHandles } from '../modes/games'
import { scanNetstatV2 } from '../modes/network'
import { scanRegistryDeepV2, scanPrefetchV2, scanRegistryForCheats } from '../modes/registry'
import { scanBrowserHistory } from '../modes/browser'
import { scanDmaDevices, checkIommuStatus, scanScheduledTasks } from '../modes/dma'
import { runFullUsbDeviceScan } from '../modes/usb-devices'
import { scanByovd } from '../modes/byovd'
import { scanAntiDebug } from '../modes/anti-debug'
import { safeCall, safeSpread } from '../utils/safe-spread'
import { runApcScan } from '../modes/apc-detector'
import { runForensicScan } from '../forensic-traces'
import { runAntiForensicScan } from '../anti-forensic'
import { runPcCleanerScan } from '../pc-cleaner-detection'
import { runAntiTamperScan } from '../anti-tamper'
import { runSelfIntegrityScan } from '../self-integrity'
import { runSelfProtectCheck } from '../self-protect'
import { runParallel } from '../workers/worker-pool'
import { scanProcessForAmsiEtw } from '../modes/etw-amsi'
import { scanGameMemory, detectCefDebugPorts } from '../modes/game-memory'
import { runNetworkIntel } from '../modes/network-intel'
import { analyzeBehavior, behaviorReportToScanResults } from '../behavior-engine'
import { buildBehaviorProfile, profileToScanResult } from '../behavior-profile'
import { scanRwxAndThreads, rwxResultToScanResult } from '../rwx-scanner'
import { scanDiskVsMemory, dvmResultToScanResult } from '../disk-vs-memory'
import { type ScanResult, sendProgress, clearFindingDedup, parsePsJson, ctx, hasFileChanged, markFileScanned } from '../types'

export async function runFullScan(win: BrowserWindow | null): Promise<{ results: ScanResult[]; filesScanned: number }> {
  const results: ScanResult[] = []
  let filesScanned = 0
  const signal = ctx.abortController?.signal
  const aborted = () => signal?.aborted ?? false

  clearFindingDedup()

  // Phase 0: Anti-Tamper + Self-Integrity + Runtime Self-Protection
  await sendProgress(win, { phase: 'scanning', currentDir: 'Self-integrity verification...', filesFound: results.length, filesScanned, totalDirs: 9, dirsDone: 0 })
  results.push(...safeCall('runAntiTamperScan', () => runAntiTamperScan()))
  // Server-side verified integrity check (async — fetches expected hash from server)
  try {
    results.push(...await runSelfIntegrityScan())
  } catch (err) { console.error('[full-scan] runSelfIntegrityScan crashed:', (err as Error).message) }
  results.push(...safeCall('runSelfProtectCheck', () => runSelfProtectCheck()))
  if (aborted()) return { results, filesScanned }

  await sendProgress(win, { phase: 'scanning', currentDir: 'Advanced process scanning...', filesFound: results.length, filesScanned, totalDirs: 9, dirsDone: 1 })
  results.push(...safeCall('scanRunningProcessesV2', () => scanRunningProcessesV2()))
  results.push(...safeCall('scanBehavioralMasquerading', () => scanBehavioralMasquerading()))
  results.push(...safeCall('scanAntiDebug', () => scanAntiDebug()))
  if (aborted()) return { results, filesScanned }

  // Phase 1b: USB/PCI device inventory scan
  await sendProgress(win, { phase: 'scanning', currentDir: 'USB & PCI device inventory...', filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 2 })
  try {
    results.push(...await runFullUsbDeviceScan(signal))
  } catch (err) {
    if (aborted()) return { results, filesScanned }
    console.warn('[scanner] USB device scan failed:', (err as Error).message)
  }
  if (aborted()) return { results, filesScanned }

  // Phase 2: heuristic file scan
  await sendProgress(win, { phase: 'scanning', currentDir: `Heuristic file scan (${EXTENDED_SCAN_PATHS.length} directories)...`, filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 3 })
  for (const dir of EXTENDED_SCAN_PATHS) {
    await sendProgress(win, { phase: 'scanning', currentDir: dir, filesFound: results.length, filesScanned, totalDirs: 10, dirsDone: 2 })
    try {
      const filePaths: string[] = []
      let dirFileCount = 0
      const DIR_FILE_LIMIT = 2000
      for await (const filePath of walkDirAsync(dir, signal)) {
        dirFileCount++
        if (dirFileCount > DIR_FILE_LIMIT) {
          console.warn(`[Predator] Directory file limit reached: ${dir} (${dirFileCount})`)
          break
        }
        filePaths.push(filePath)
      }

      if (filePaths.length > 0) {
        try {
          const sigResults = await batchCheckSignatures(filePaths, 500, signal)
          const sigChecked = [...sigResults.values()].filter(Boolean).length
          const sigTotal = [...sigResults.values()].filter(v => v === false).length + sigChecked
          if (sigTotal > 0) {
            console.log(`  🔐 Batch signature check: ${sigChecked}/${sigTotal} valid (${(sigChecked/sigTotal*100).toFixed(0)}%)`)
          }
        } catch (err) {
          if (aborted()) return { results, filesScanned }
          console.warn('[scanner] batch signature check failed:', (err as Error).message)
        }
      }

      if (filePaths.length > 0) {
        const scanResults = await runParallel(filePaths, async (filePath) => {
          // E11: Incremental scan — skip unchanged files
          let st: Stats | undefined
          try { st = await fsp.stat(filePath) } catch { return null }
          if (st && !hasFileChanged(ctx, filePath, st.mtimeMs)) {
            return null
          }
          let hr = await heuristicFileScan(filePath, signal)
          // Mark file as scanned for incremental mode
          if (st) markFileScanned(ctx, filePath, st.mtimeMs)
          let riskScore = hr?.riskScore || 0
          const shadowHits = hr?.shadowRuleHits

          if (shadowHits && shadowHits.length > 0 && riskScore < 20) {
            const ext2 = path.extname(filePath).toLowerCase()
            const ruleName = shadowHits[0]?.match(/\[([^\]]+)\]/)?.[1] || 'unknown'
            let shadowSha256: string | undefined
            if (ext2 === '.exe' || ext2 === '.dll' || ext2 === '.sys') {
              try {
                const h = crypto.createHash('sha256')
                const st = await fsp.stat(filePath)
                const buf = await readFilePrefix(filePath, Math.min(st.size, 50 * 1024 * 1024), signal)
                h.update(buf)
                shadowSha256 = h.digest('hex')
              } catch (err) { console.warn('[scanner] shadow sha256 failed:', (err as Error).message) }
            }
            ctx.shadowFindings.push({
              path: filePath, fileName: path.basename(filePath), type: 'file', risk: 'low',
              matches: shadowHits.slice(0, 5), size: 0, modifiedAt: new Date().toISOString(), ruleName, sha256: shadowSha256,
            })
            if (riskScore <= 0) return null
          }

          const fpLower = filePath.toLowerCase()
          if (fpLower.includes('downloads') || fpLower.includes('download') || fpLower.includes('desktop') || fpLower.includes('temp') || fpLower.includes('загрузки')) {
            riskScore += 10
          }

          const ext = path.extname(filePath).toLowerCase()
          if ((ext === '.exe' || ext === '.dll') && riskScore < 40) {
            const fuzzyMatch = fuzzyMatchFile(filePath, 25)
            if (fuzzyMatch && fuzzyMatch.matched) {
              riskScore = Math.max(riskScore, 60)
              if (!hr) hr = { riskScore: 60, suspicions: [] }
              hr.suspicions.push(`fuzzy-hash:matched (distance=${fuzzyMatch.distance})`)
            }
          }

          if (ctx.escalationBonus > 0 && riskScore > 10) {
            riskScore += ctx.escalationBonus
            if (!hr) hr = { riskScore: ctx.escalationBonus, suspicions: [] }
            hr.suspicions.push(`persistent-profile:escalated +${ctx.escalationBonus} (repeated suspicious activity)`)
          }

          if (hr && riskScore > 20) {
            const risk = riskScore > 80 ? 'high' : riskScore > 50 ? 'medium' : 'low'
            let sha256Hash: string | undefined
            let partialHash: string | undefined
            let fileSize = 0
            try {
              const stat2 = await fsp.stat(filePath)
              fileSize = stat2.size
              const partialBuf = await readFilePrefix(filePath, Math.min(stat2.size, 64 * 1024), signal)
              partialHash = crypto.createHash('sha256').update(partialBuf).digest('hex')
              if (risk === 'high' && (ext === '.exe' || ext === '.dll' || ext === '.sys')) {
                const h = crypto.createHash('sha256')
                const fullBuf = await readFilePrefix(filePath, Math.min(stat2.size, 50 * 1024 * 1024), signal)
                h.update(fullBuf)
                sha256Hash = h.digest('hex')
              }
            } catch { /* hash optional */ }

            return {
              path: filePath, fileName: path.basename(filePath), type: 'file' as const, risk,
              matches: hr.suspicions.slice(0, 5), size: fileSize, modifiedAt: new Date().toISOString(),
              sha256: sha256Hash, partialHash, hasValidSignature: hr.hasValidSignature,
            } satisfies ScanResult
          }
          return null
        }, { concurrency: 4, signal: ctx.abortController?.signal })

        for (const r of scanResults) { if (r) results.push(r) }
        filesScanned += filePaths.length
      }
    } catch (err) { console.warn('[scanner] file walk failed:', (err as Error).message) }
  }
  if (aborted()) return { results, filesScanned }

  // Phase 3-5: registry + prefetch + network
  await sendProgress(win, { phase: 'scanning', currentDir: 'Registry + prefetch + network...', filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 4 })
  results.push(...safeCall('scanRegistryDeepV2', () => scanRegistryDeepV2()))
  results.push(...safeCall('scanPrefetchV2', () => scanPrefetchV2()))
  results.push(...safeCall('scanNetstatV2', () => scanNetstatV2()))
  await sendProgress(win, { phase: 'scanning', currentDir: 'Parallel: exec + memory + behavior...', filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 6 })
  results.push(...safeCall('scanMasqueradingProcesses', () => scanMasqueradingProcesses()))
  if (aborted()) return { results, filesScanned }

  // Phase 5a: network intel — proxy/VPN/C2 detection (E15)
  await sendProgress(win, { phase: 'scanning', currentDir: 'Network threat intel...', filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 6 })
  results.push(...safeCall('runNetworkIntel', () => runNetworkIntel()))
  if (aborted()) return { results, filesScanned }

  // Phase 5b: game integrity + modules + handles
  await sendProgress(win, { phase: 'scanning', currentDir: 'Game integrity...', filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 6 })
  try {
    results.push(...await scanGameIntegrity(signal))
    results.push(...await scanGameModules(signal))
  } catch (err) {
    if (aborted()) return { results, filesScanned }
    console.warn('[scanner] game signature scan failed:', (err as Error).message)
  }
  results.push(...safeCall('scanOpenHandles', () => scanOpenHandles()))
  // E14: Game memory pattern scan + CEF debug port detection
  await sendProgress(win, { phase: 'scanning', currentDir: 'Game memory analysis...', filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 6 })
  results.push(...safeCall('scanGameMemory', () => scanGameMemory()))
  results.push(...safeCall('detectCefDebugPorts', () => detectCefDebugPorts()))
  if (aborted()) return { results, filesScanned }

  // Phase 5c: named pipes + WMI + AMSI/ETW + BYOVD
  await sendProgress(win, { phase: 'scanning', currentDir: 'IPC & persistence...', filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 6 })
  results.push(...safeCall('scanNamedPipes', () => scanNamedPipes()))
  results.push(...safeCall('scanWmiPersistence', () => scanWmiPersistence()))
  results.push(...safeCall('runApcScan', () => runApcScan()))
  try {
    results.push(...await scanByovd(signal))
  } catch (err) {
    if (aborted()) return { results, filesScanned }
    console.warn('[scanner] BYOVD scan failed:', (err as Error).message)
  }
  if (aborted()) return { results, filesScanned }

  try {
    const psOut = await execPowerShellAsync(
      `Get-Process | Where-Object { $_.Modules } | Select-Object Name, Id, @{N='Mods';E={$_.Modules | Select -Expand ModuleName}} | ConvertTo-Json -Depth 3`,
      { timeout: 10000, signal },
    )
    const processes = parsePsJson<{ Name?: string; Id?: number; Mods?: string[] }>(psOut || '')
    for (const proc of processes) {
      if (aborted()) break
      const mods: string[] = proc.Mods || []
      const patchResult = await scanProcessForAmsiEtw(Number(proc.Id), (proc.Name || '').toLowerCase())
      if (patchResult && (patchResult.amsiPatched || patchResult.etwPatched) && patchResult.riskScore > 20) {
        results.push({
          path: `process:${proc.Name} (PID: ${proc.Id})`,
          fileName: `${proc.Name} — AMSI/ETW patch detected`, type: 'process', risk: 'high',
          matches: ['AMSI patching / ETW evasion detected', 'Process bypassing AMSI scanning'],
          size: 0, modifiedAt: new Date().toISOString(),
        })
      }
      try {
        const profile = buildBehaviorProfile(Number(proc.Id), (proc.Name || '').toLowerCase(), mods)
        const pr = profileToScanResult(profile)
        if (pr) results.push(pr)
      } catch (err) { console.warn('[scanner] behavior profile failed:', (err as Error).message) }
      try {
        const rwxResult = scanRwxAndThreads(Number(proc.Id), (proc.Name || '').toLowerCase())
        if (rwxResult) { const r = rwxResultToScanResult(rwxResult); if (r) results.push(r) }
      } catch (err) { console.warn('[scanner] RWX scan failed:', (err as Error).message) }
      try {
        const dvmResult = scanDiskVsMemory(Number(proc.Id), (proc.Name || '').toLowerCase())
        if (dvmResult) { const r = dvmResultToScanResult(dvmResult); if (r) results.push(r) }
      } catch (err) { console.warn('[scanner] disk-vs-memory failed:', (err as Error).message) }
    }
  } catch (err) { console.warn('[scanner] PowerShell AMSI/ETW scan failed:', (err as Error).message) }
  if (aborted()) return { results, filesScanned }

  // Phase 6: DMA + scheduled tasks + IOMMU
  await sendProgress(win, { phase: 'scanning', currentDir: 'DMA devices + IOMMU...', filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 8 })
  try {
    results.push(...await scanDmaDevices(signal))
  } catch (err) {
    if (aborted()) return { results, filesScanned }
    console.warn('[scanner] DMA device scan failed:', (err as Error).message)
  }
  try {
    results.push(...await checkIommuStatus(signal))
  } catch (err) {
    if (aborted()) return { results, filesScanned }
    console.warn('[scanner] IOMMU scan failed:', (err as Error).message)
  }
  await sendProgress(win, { phase: 'scanning', currentDir: 'Scheduled tasks...', filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 8 })
  try {
    results.push(...await scanScheduledTasks(signal))
  } catch (err) {
    if (aborted()) return { results, filesScanned }
    console.warn('[scanner] scheduled task scan failed:', (err as Error).message)
  }
  if (aborted()) return { results, filesScanned }

  await sendProgress(win, { phase: 'scanning', currentDir: 'Registry cheat scan...', filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 9 })
  results.push(...safeCall('scanRegistryForCheats', () => scanRegistryForCheats()))
  if (aborted()) return { results, filesScanned }

  await sendProgress(win, { phase: 'analyzing', currentDir: 'Browser history...', filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 10 })
  try {
    const bh = await scanBrowserHistory(ALL_CHEAT_KEYWORDS)
    results.push(...safeSpread('scanBrowserHistory', bh))
  } catch (err) { console.error('[scan] scanBrowserHistory crashed:', (err as Error).message || err) }
  if (aborted()) return { results, filesScanned }

  await sendProgress(win, { phase: 'scanning', currentDir: 'Forensic artifact scan...', filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 11 })
  results.push(...safeCall('runForensicScan', () => runForensicScan()))
  if (aborted()) return { results, filesScanned }

  await sendProgress(win, { phase: 'scanning', currentDir: 'Anti-forensic integrity check...', filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 12 })
  results.push(...safeCall('runAntiForensicScan', () => runAntiForensicScan()))
  if (aborted()) return { results, filesScanned }

  await sendProgress(win, { phase: 'scanning', currentDir: 'PC cleaning detection...', filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 13 })
  results.push(...safeCall('runPcCleanerScan', () => runPcCleanerScan()))

  // E17: Cross-process behavioral correlation (injector-victim pairs, attack chains)
  await sendProgress(win, { phase: 'analyzing', currentDir: 'Behavioral correlation analysis...', filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 13 })
  const behaviorReport = analyzeBehavior()
  results.push(...behaviorReportToScanResults(behaviorReport))

  await sendProgress(win, { phase: 'done', currentDir: '', filesFound: results.length, filesScanned, totalDirs: 13, dirsDone: 13 })
  return { results, filesScanned }
}
