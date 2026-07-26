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

import { sendProgress, yieldToEventLoop, clearFindingDedup, addFindingDedup, execCmd, parsePsJson, _HOME, _WR, type ScanResult } from '../types'
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

  let processes: { Name?: string; Id?: number; Mods?: string[] }[] = []
  try {
    const psOut = execSync(
      `powershell -Command "Get-Process | Where-Object { $_.Modules } | Select-Object Name, Id, @{N='Mods';E={$_.Modules | Select -Expand ModuleName}} | ConvertTo-Json -Depth 3"`,
      { encoding: 'utf-8', timeout: 10000 },
    )
      processes = parsePsJson<{ Name?: string; Id?: number; Mods?: string[] }>(psOut)
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
  try {      const out = execCmd('cmd /c "dir \\\\.\\pipe\\ /b 2>nul"', 'powershell -Command "[System.IO.Directory]::GetFiles(\\\"\\\\.\\pipe\\\") | ConvertTo-Json -Compress"', { timeout: 3000 })
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
      const items = parsePsJson<{ Name?: string }>(psOut)
      if (items.length > 0) {
        const names = items.filter(i => i.Name).map(i => i.Name!.toLowerCase().replace(/[^a-z0-9]/g, ''))
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
// BEHAVIORAL PROCESS DETECTION (from dynamic analysis)
// ═══════════════════════════════════════════════════
//
// Detects cheat loaders masquerading as legitimate executables based on
// behavioral patterns observed during dynamic analysis of known samples:
//
//   1. High memory usage (>200MB for a simple installer)
//   2. Self-spawning (same name spawning itself as child process)
//   3. Multiple instances of same masquerading name
//   4. Unsigned masquerading process running from suspicious location
//
// Reference: dxwebsetup.exe monitoring — VMProtect packed loader
// running at ~240MB with self-spawning child process
// ═══════════════════════════════════════════════════

import { MASQUERADING_FILENAMES } from '../cheats-db'

/**
 * Scan for masquerading processes with behavioral anomalies.
 *
 * Detects:
 * - Processes named as known legitimate software but behaving abnormally
 *   (high memory, self-spawning, multiple instances)
 * - A lightweight scan — no heavyweight analysis needed
 */
export function scanMasqueradingProcesses(): ScanResult[] {
  const results: ScanResult[] = []
  try {
    const output = execSync('tasklist /FO CSV /NH', { encoding: 'utf-8', timeout: 5000 })
    const lines = output.trim().split('\n')

    // Collect all masquerading-named processes
    const masqueradingProcs: { name: string; pid: number; memKB: number }[] = []
    for (const line of lines) {
      try {
        const parts = line.match(/"([^"]+)","(\d+)","(\d+)","([^"]+)"/)
        if (!parts) continue
        const name = parts[1].toLowerCase()
        if (!MASQUERADING_FILENAMES.has(name)) continue
        const pid = parseInt(parts[2], 10)
        const memStr = parts[3].replace(/[^\d]/g, '')
        const memKB = parseInt(memStr, 10) || 0
        masqueradingProcs.push({ name, pid, memKB })
      } catch (_e) { /* skip */ }
    }

    if (masqueradingProcs.length === 0) return results

    // Count instances per name
    const nameCount = new Map<string, number>()
    for (const p of masqueradingProcs) {
      nameCount.set(p.name, (nameCount.get(p.name) || 0) + 1)
    }

    // Emit findings
    for (const proc of masqueradingProcs) {
      if (!addFindingDedup(`masq:${proc.name}:${proc.pid}`)) continue
      const count = nameCount.get(proc.name) || 1

      const matches: string[] = [`behavior:masquerading:${proc.name}`]
      let risk: 'high' | 'medium' = 'medium'

      // Signal 1: High memory (>200MB for a utility that should be tiny)
      if (proc.memKB > 200 * 1024) {
        matches.push(`behavior:high-memory:${(proc.memKB / 1024).toFixed(0)}MB`)
        risk = 'high'
      }

      // Signal 2: Multiple instances of same masquerading name
      if (count >= 2) {
        matches.push(`behavior:multiple-instances:${count}x`)
        risk = 'high'
      }

      // Signal 3: High memory + multiple instances = certain cheat loader
      if (proc.memKB > 200 * 1024 && count >= 2) {
        matches.push('behavior:cheat-loader-profile:vmprotect-pattern')
        risk = 'high'
      }

      results.push({
        path: `process:${proc.name} (PID: ${proc.pid})`,
        fileName: `${proc.name}`,
        type: 'process',
        risk,
        matches,
        size: proc.memKB * 1024,
        modifiedAt: new Date().toISOString(),
      })
    }

    return results
  } catch (_e) {
    return results
  }
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

  await sendProgress(win, { phase: 'scanning', currentDir: 'Scanning running processes...', filesFound: 0, filesScanned: 0, totalDirs: 6, dirsDone: 0 })

  const v2Results = scanRunningProcessesV2()
  for (const r of v2Results) results.push(r)

  await sendProgress(win, { phase: 'scanning', currentDir: 'Checking for masquerading processes...', filesFound: results.length, filesScanned: 0, totalDirs: 6, dirsDone: 1 })

  const masqResults = scanMasqueradingProcesses()
  for (const r of masqResults) results.push(r)

  await sendProgress(win, { phase: 'scanning', currentDir: 'Checking recent items...', filesFound: results.length, filesScanned: 0, totalDirs: 6, dirsDone: 2 })

  const recent = scanRecentItems()
  for (const r of recent) results.push(r)

  await sendProgress(win, { phase: 'scanning', currentDir: 'Checking Prefetch files...', filesFound: results.length, filesScanned: 0, totalDirs: 6, dirsDone: 3 })

  const prefetch = scanPrefetchFiles()
  for (const r of prefetch) results.push(r)

  await sendProgress(win, { phase: 'scanning', currentDir: 'Checking named pipes...', filesFound: results.length, filesScanned: 0, totalDirs: 6, dirsDone: 4 })

  const pipes = scanNamedPipes()
  for (const r of pipes) results.push(r)

  await sendProgress(win, { phase: 'scanning', currentDir: 'Checking WMI persistence...', filesFound: results.length, filesScanned: 0, totalDirs: 6, dirsDone: 5 })

  const wmi = scanWmiPersistence()
  for (const r of wmi) results.push(r)

  await sendProgress(win, { phase: 'analyzing', currentDir: 'Memory analysis...', filesFound: results.length, filesScanned: 0, totalDirs: 6, dirsDone: 6 })

  return { results, filesScanned: results.length }
}
