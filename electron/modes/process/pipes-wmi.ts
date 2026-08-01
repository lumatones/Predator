/**
 * Predator — Named Pipes & WMI Persistence Scanner
 *
 * Extracted from processes.ts. Detects cheat-related named pipes and
 * WMI event subscriptions used for persistence.
 */

import { execPowerShell } from '../../utils/exec'
import * as fs from 'fs'
import * as path from 'path'

import { addFindingDedup, execCmd, parsePsJson, type ScanResult, _HOME } from '../../types'
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
    const psOut = execPowerShell(`Get-WmiObject -Class StdRegProv -Namespace root\\\\default -ErrorAction SilentlyContinue | Out-Null; Get-CimInstance -ClassName __ClassCreationEvent -Namespace 'root\\\\subscription' -ErrorAction SilentlyContinue | Select-Object * | ConvertTo-Json -Compress`, { timeout: 8000 }) || ''
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
  } catch (err) { console.warn('[pipes-wmi] WMI failed:', (err as Error).message) }
  return results
}

// ═══════════════════════════════════════════════════
// STARTUP FOLDER PERSISTENCE (KUDU-inspired)
// ═══════════════════════════════════════════════════

/** Windows startup folder paths */
const STARTUP_PATHS = [
  path.join(_HOME, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
  'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',
]

const SUSPICIOUS_STARTUP_EXTS = new Set(['.exe', '.bat', '.ps1', '.vbs', '.cmd', '.js', '.vbe', '.wsf', '.scr'])

export function scanStartupFolder(): ScanResult[] {
  const results: ScanResult[] = []
  for (const startupDir of STARTUP_PATHS) {
    try {
      if (!fs.existsSync(startupDir)) continue
      for (const entry of fs.readdirSync(startupDir)) {
        const ext = path.extname(entry).toLowerCase()
        if (!SUSPICIOUS_STARTUP_EXTS.has(ext)) continue
        const entryPath = path.join(startupDir, entry)
        const lower = entry.toLowerCase()
        const matches: string[] = []
        const cheatKw = ['cheat', 'hack', 'inject', 'bypass', 'loader', 'spoofer', 'dma', 'menu', 'mod']
        for (const kw of cheatKw) {
          if (lower.includes(kw)) matches.push(`startup-name:${kw}`)
        }
        const nameMatches = matchKnownCheat(entry)
        if (nameMatches.length > 0) matches.push(...nameMatches)
        let stat: fs.Stats | undefined
        try { stat = fs.statSync(entryPath) } catch { /* skip */ }
        if (stat && Date.now() - stat.mtimeMs < 30 * 24 * 60 * 60 * 1000) {
          matches.push('Recently modified (within 30 days)')
        }
        if (matches.length > 0 && addFindingDedup(`startup:${entryPath}`)) {
          results.push({
            path: entryPath, fileName: `Startup folder: ${entry}`, type: 'software',
            risk: matches.length >= 2 ? 'high' : 'medium', matches: matches.slice(0, 5),
            size: stat?.size ?? 0, modifiedAt: stat?.mtime.toISOString() ?? new Date().toISOString(),
          })
        }
      }
    } catch (err) { console.warn('[startup] failed:', (err as Error).message) }
  }
  return results
}
