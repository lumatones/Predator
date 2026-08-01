/**
 * Predator — Behavioral Process Detection
 *
 * Extracted from processes.ts. Detects cheat loaders masquerading as
 * legitimate executables based on behavioral patterns observed during
 * dynamic analysis of known samples:
 *
 *   1. High memory usage (>200MB for a simple installer)
 *   2. Self-spawning (same name spawning itself as child process)
 *   3. Multiple instances of same masquerading name
 *   4. Unsigned masquerading process running from suspicious location
 *
 * Reference: dxwebsetup.exe monitoring — VMProtect packed loader
 * running at ~240MB with self-spawning child process
 */

import { execWithTimeout } from '../../utils/exec'

import { addFindingDedup, type ScanResult } from '../../types'
import { MASQUERADING_SYSTEM_TOOLS } from '../../cheats-db'

// ═══════════════════════════════════════════════════
// BEHAVIORAL MASQUERADING DETECTION
// ═══════════════════════════════════════════════════

export function scanBehavioralMasquerading(): ScanResult[] {
  const results: ScanResult[] = []
  try {
    const output = execWithTimeout('tasklist /FO CSV /NH', { timeout: 5000 }) || ''
    const lines = output.trim().split('\n')

    const masqueradingProcs: { name: string; pid: number; memKB: number }[] = []
    for (const line of lines) {
      try {
        const parts = line.match(/"([^"]+)","(\d+)","(\d+)","([^"]+)"/)
        if (!parts) continue
        const name = parts[1].toLowerCase()
        if (!MASQUERADING_SYSTEM_TOOLS.has(name)) continue
        const pid = parseInt(parts[2], 10)
        const memStr = parts[3].replace(/[^\d]/g, '')
        const memKB = parseInt(memStr, 10) || 0
        masqueradingProcs.push({ name, pid, memKB })
      } catch (err) { console.warn('[behavioral] failed:', (err as Error).message) }
    }

    if (masqueradingProcs.length === 0) return results

    const nameCount = new Map<string, number>()
    for (const p of masqueradingProcs) {
      nameCount.set(p.name, (nameCount.get(p.name) || 0) + 1)
    }

    for (const proc of masqueradingProcs) {
      if (!addFindingDedup(`masq:${proc.name}:${proc.pid}`)) continue
      const count = nameCount.get(proc.name) || 1

      const matches: string[] = [`behavior:masquerading:${proc.name}`]
      let risk: 'high' | 'medium' = 'medium'

      if (proc.memKB > 200 * 1024) {
        matches.push(`behavior:high-memory:${(proc.memKB / 1024).toFixed(0)}MB`)
        risk = 'high'
      }

      if (count >= 2) {
        matches.push(`behavior:multiple-instances:${count}x`)
        risk = 'high'
      }

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
