/**
 * Predator — Process Scan Mode
 *
 * Scans running processes, recent items, prefetch files,
 * and performs advanced module/memory/behavior analysis.
 */

import { execSync } from 'child_process'
import fs from 'fs'
import path from 'path'
import type { BrowserWindow } from 'electron'

import { sendProgress, yieldToEventLoop, clearFindingDedup, addFindingDedup, _HOME, _WR, type ScanResult } from '../types'
import { SUSPICIOUS_CATEGORIES, matchKnownCheat, checkDigitalSignature, heuristicFileScan } from '../heuristic'
import { isTrustedPath } from '../cheat-rules'

// ═══════════════════════════════════════════════════
// RUNNING PROCESSES
// ═══════════════════════════════════════════════════

export function scanRunningProcesses(): ScanResult[] {
  const results: ScanResult[] = []
  try {
    const output = execSync('tasklist /FO CSV /NH', { encoding: 'utf-8', timeout: 5000 })
    for (const line of output.trim().split('\n')) {
      try {
        const parts = line.match(/"([^"]+)","(\d+)","(\d+)","([^"]+)"/)
        if (!parts) continue
        const name = parts[1].toLowerCase()
        const pid = parseInt(parts[2], 10)
        const memStr = parts[3].replace(/[^\d]/g, '')
        const memory = parseInt(memStr, 10) || 0

        const matches = matchKnownCheat(name)
        if (matches.length > 0) {
          results.push({
            path: `process:${parts[1]} (PID: ${pid})`, fileName: parts[1], type: 'process',
            risk: matches.length >= 2 ? 'high' : 'medium',
            matches, size: memory * 1024, modifiedAt: new Date().toISOString(),
          })
        }
      } catch (_e) { /* skip */ }
    }
  } catch (_e) { /* tasklist failed */ }
  return results
}

function scanRecentItems(): ScanResult[] {
  const results: ScanResult[] = []
  const recentDir = path.join(_HOME, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Recent')
  try {
    if (!fs.existsSync(recentDir)) return results
    for (const item of fs.readdirSync(recentDir)) {
      const matches = matchKnownCheat(item)
      if (matches.length > 0) {
        const itemPath = path.join(recentDir, item)
        try {
          const stat = fs.statSync(itemPath)
          results.push({ path: itemPath, fileName: item, type: 'file', risk: matches.length >= 2 ? 'high' : 'medium', matches, size: stat.size, modifiedAt: stat.mtime.toISOString() })
        } catch (_e) { /* skip */ }
      }
    }
  } catch (_e) { /* skip */ }
  return results
}

function scanPrefetchFiles(): ScanResult[] {
  const results: ScanResult[] = []
  const prefetchDir = path.join(_WR, 'Prefetch')
  try {
    if (!fs.existsSync(prefetchDir)) return results
    for (const file of fs.readdirSync(prefetchDir)) {
      const matches = matchKnownCheat(file)
      if (matches.length > 0) {
        const filePath = path.join(prefetchDir, file)
        try {
          const stat = fs.statSync(filePath)
          results.push({ path: filePath, fileName: file, type: 'file', risk: matches.length >= 2 ? 'high' : 'medium', matches, size: stat.size, modifiedAt: stat.mtime.toISOString() })
        } catch (_e) { /* skip */ }
      }
    }
  } catch (_e) { /* skip */ }
  return results
}

/** v2: Advanced process scan — checks loaded DLLs and modules via PowerShell */
export function scanRunningProcessesV2(): ScanResult[] {
  const results: ScanResult[] = []

  const basicResults = scanRunningProcesses()
  for (const r of basicResults) {
    if (addFindingDedup(`proc:${r.fileName}`)) results.push(r)
  }

  let processes: any[] = []
  try {
    const psOut = execSync(
      `powershell -Command "Get-Process | Where-Object { $_.Modules } | Select-Object Name, Id, @{N='Mods';E={$_.Modules | Select -Expand ModuleName}} | ConvertTo-Json -Depth 3"`,
      { encoding: 'utf-8', timeout: 10000 },
    )
    if (psOut && psOut.trim().length >= 5) {
      const parsed = JSON.parse(psOut)
      processes = Array.isArray(parsed) ? parsed : [parsed]
    }
  } catch (_e) { /* PowerShell failed */ }

  if (processes.length === 0) return results

  // Module analysis
  for (const proc of processes) {
    const procName = (proc.Name || '').toLowerCase()
    const modules: string[] = proc.Mods || []

    for (const modName of modules) {
      if (!modName || typeof modName !== 'string') continue
      const modLower = modName.toLowerCase()

      for (const [catName, cat] of Object.entries(SUSPICIOUS_CATEGORIES)) {
        for (const name of cat.names) {
          if (modLower.includes(name) && addFindingDedup(`mod:${procName}:${modLower}`)) {
            results.push({
              path: `process:${proc.Name} (PID: ${proc.Id})`,
              fileName: `Module: ${modName}`,
              type: 'process',
              risk: cat.risk === 'CRITICAL' || cat.risk === 'HIGH' ? 'high' : 'medium',
              matches: [`module:${name} (${catName})`, `process:${procName}`],
              size: 0,
              modifiedAt: new Date().toISOString(),
            })
          }
        }
      }
    }
  }

  return results
}

// ═══════════════════════════════════════════════════
// NAMED PIPES & WMI PERSISTENCE
// ═══════════════════════════════════════════════════

export function scanNamedPipes(): ScanResult[] {
  const results: ScanResult[] = []
  try {
    const out = execSync('cmd /c "dir \\\\.\\pipe\\ /b 2>nul"', 'powershell -Command "[System.IO.Directory]::GetFiles(\\\"\\\\.\\pipe\\\") | ConvertTo-Json -Compress"', { timeout: 3000 })
    if (!out.trim()) return results
    const pipes = out.trim().split('\n')
    for (const pipe of pipes) {
      const lower = pipe.toLowerCase()
      if (lower.includes('cheat') || lower.includes('inject') || lower.includes('hook') || lower.includes('bypass') || lower.includes('dma')) {
        if (addFindingDedup(`pipe:${lower}`)) {
          results.push({
            path: `\\\\.\\pipe\\${pipe}`, fileName: `Named pipe: ${pipe.trim()}`, type: 'software', risk: 'high',
            matches: [`suspicious-pipe:${lower}`],
            size: 0, modifiedAt: new Date().toISOString(),
          })
        }
      }
    }
  } catch (_e) { /* skip */ }
  return results
}

export function scanWmiPersistence(): ScanResult[] {
  const results: ScanResult[] = []
  try {
    const psOut = execSync(
      `powershell -Command "Get-WmiObject -Class StdRegProv -Namespace root\\default -ErrorAction SilentlyContinue | Out-Null; Get-CimInstance -ClassName __ClassCreationEvent -Namespace 'root\\subscription' -ErrorAction SilentlyContinue | Select-Object * | ConvertTo-Json -Compress"`,
      { encoding: 'utf-8', timeout: 8000 },
    ).toString()
    if (psOut && psOut.trim().length > 10) {
      const parsed = JSON.parse(psOut)
      const items = Array.isArray(parsed) ? parsed : [parsed]
      if (items.length > 0) {
        const names = items.filter((i: any) => i.Name).map((i: any) => i.Name.toLowerCase().replace(/[^a-z0-9]/g, ''))
        for (const name of names) {
          const matches = matchKnownCheat(name)
          if (matches.length > 0 && addFindingDedup(`wmi:${name}`)) {
            results.push({
              path: 'WMI:Persistence', fileName: `WMI subscription: ${name}`, type: 'software', risk: 'high',
              matches: [...matches, 'WMI persistence mechanism'],
              size: 0, modifiedAt: new Date().toISOString(),
            })
          }
        }
      }
    }
  } catch (_e) { /* skip */ }
  return results
}

// ═══════════════════════════════════════════════════
// PROCESS MEMORY ANALYSIS
// ═══════════════════════════════════════════════════

import { dumpAndAnalyze, dumpProcessMemory } from '../memory-dump'
import { analyzeApiHashingInDump } from '../api-hashing'
import { scanProcessForAmsiEtw } from '../etw-amsi-patch'
import { buildBehaviorProfile, profileToScanResult } from '../behavior-profile'
import { scanRwxAndThreads, rwxResultToScanResult } from '../rwx-scanner'
import { scanDiskVsMemory, dvmResultToScanResult } from '../disk-vs-memory'

// ═══════════════════════════════════════════════════
// RUN PROCESS SCAN (orchestrator for this mode)
// ═══════════════════════════════════════════════════

export async function runProcessScan(win: BrowserWindow | null): Promise<{ results: ScanResult[]; filesScanned: number }> {
  clearFindingDedup()
  const results: ScanResult[] = []

  await sendProgress(win, { phase: 'scanning', currentDir: 'Scanning running processes...', filesFound: 0, filesScanned: 0, totalDirs: 5, dirsDone: 0 })

  const v2Results = scanRunningProcessesV2()
  for (const r of v2Results) results.push(r)

  await sendProgress(win, { phase: 'scanning', currentDir: 'Checking recent items...', filesFound: results.length, filesScanned: 0, totalDirs: 5, dirsDone: 1 })

  const recent = scanRecentItems()
  for (const r of recent) results.push(r)

  await sendProgress(win, { phase: 'scanning', currentDir: 'Checking Prefetch files...', filesFound: results.length, filesScanned: 0, totalDirs: 5, dirsDone: 2 })

  const prefetch = scanPrefetchFiles()
  for (const r of prefetch) results.push(r)

  await sendProgress(win, { phase: 'scanning', currentDir: 'Checking named pipes...', filesFound: results.length, filesScanned: 0, totalDirs: 5, dirsDone: 3 })

  const pipes = scanNamedPipes()
  for (const r of pipes) results.push(r)

  await sendProgress(win, { phase: 'scanning', currentDir: 'Checking WMI persistence...', filesFound: results.length, filesScanned: 0, totalDirs: 5, dirsDone: 4 })

  const wmi = scanWmiPersistence()
  for (const r of wmi) results.push(r)

  await sendProgress(win, { phase: 'analyzing', currentDir: 'Memory analysis...', filesFound: results.length, filesScanned: 0, totalDirs: 5, dirsDone: 5 })

  return { results, filesScanned: results.length }
}
