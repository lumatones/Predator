/**
 * Predator — Named Pipes & WMI Persistence Scanner
 *
 * Extracted from processes.ts. Detects cheat-related named pipes and
 * WMI event subscriptions used for persistence.
 */

import { execSync } from 'child_process'

import { addFindingDedup, execCmd, parsePsJson, type ScanResult } from '../../types'
import { matchKnownCheat } from '../../heuristic'

// ═══════════════════════════════════════════════════
// NAMED PIPES
// ═══════════════════════════════════════════════════

export function scanNamedPipes(): ScanResult[] {
  const results: ScanResult[] = []
  try {
    const out = execCmd(
      'cmd /c "dir \\\\.\\pipe\\ /b 2>nul"',
      'powershell -Command "[System.IO.Directory]::GetFiles(\'\\\\.\\pipe\\\') | ConvertTo-Json -Compress"',
      { timeout: 3000 },
    )
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
  } catch (err) { console.warn('[pipes-wmi] failed:', (err as Error).message) }
  return results
}

// ═══════════════════════════════════════════════════
// WMI PERSISTENCE
// ═══════════════════════════════════════════════════

export function scanWmiPersistence(): ScanResult[] {
  const results: ScanResult[] = []
  try {
    const psOut = execSync(
      `powershell -Command "Get-WmiObject -Class StdRegProv -Namespace root\\\\default -ErrorAction SilentlyContinue | Out-Null; Get-CimInstance -ClassName __ClassCreationEvent -Namespace 'root\\\\subscription' -ErrorAction SilentlyContinue | Select-Object * | ConvertTo-Json -Compress"`,
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
  } catch (err) { console.warn('[pipes-wmi] failed:', (err as Error).message) }
  return results
}
