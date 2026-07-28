/**
 * Predator — Process Enumeration & Module Analysis
 *
 * Extracted from processes.ts. Scans running processes via tasklist
 * and PowerShell module enumeration for cheat signatures.
 */

import { execSync } from 'child_process'

import { addFindingDedup, parsePsJson, type ScanResult } from '../../types'
import { SUSPICIOUS_CATEGORIES, matchKnownCheat } from '../../heuristic'

// ═══════════════════════════════════════════════════
// BASIC PROCESS SCAN (tasklist)
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

// ═══════════════════════════════════════════════════
// ADVANCED PROCESS SCAN (PowerShell + modules)
// ═══════════════════════════════════════════════════

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


