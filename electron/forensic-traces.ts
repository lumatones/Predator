/**
 * Predator — Forensic Trace Detection Module
 *
 * Scans Windows forensic artifacts for evidence of cheat execution,
 * even after the user has deleted the cheat files.
 *
 * Artifacts scanned (survive file deletion):
 * 1. Prefetch files — Windows caches .pf for every executed .exe
 * 2. Amcache — AppCompat database, FOREVER persists even after deletion
 * 3. BAM — Background Activity Moderator tracks all executions
 * 4. UserAssist — ROT13-encoded GUI program execution history
 * 5. MuiCache — file path→friendly name mappings
 * 6. Windows Event Logs — Security 4688 (process creation)
 *
 * NOTE: Shimcache and Jump Lists are NOT scanned via text methods —
 * they require binary parsing (OLE, REG_BINARY) not feasible in plain Node.js.
 * For full forensic analysis, use Eric Zimmerman tools (AppCompatCacheParser, JLECmd).
 */

import { execSync } from 'child_process'
import path from 'path'
import fs from 'fs'
import { ScanResult, addFindingDedup, _WR, _HOME } from './types'
import { KNOWN_PROCESSES, KNOWN_CHEAT_FILES } from './cheats-db'

// ── ROT13 decoder (UserAssist values are ROT13 encoded) ──
function rot13(str: string): string {
  return str.replace(/[a-zA-Z]/g, c => {
    const code = c.charCodeAt(0)
    const upper = c <= 'Z' ? 90 : 122
    const rotated = code + 13
    return String.fromCharCode(rotated <= upper ? rotated : rotated - 26)
  })
}

// ── Shell helpers ──
function ps(command: string, timeout = 8000): string {
  try {
    return execSync(`powershell -NoProfile -Command "${command}"`, {
      encoding: 'utf-8',
      timeout,
      windowsHide: true,
    }).trim()
  } catch {
    return ''
  }
}

function regQuery(keyPath: string, timeout = 5000): string {
  try {
    return execSync(`reg query "${keyPath}" /s 2>nul`, {
      encoding: 'utf-8',
      timeout,
    }).trim()
  } catch {
    return ''
  }
}

// Strip non-alphanumeric chars for fuzzy matching
function stripNonAlpha(s: string): string {
  return s.replace(/[^a-z0-9]/g, '')
}

// ── All known cheat process bases — computed ONCE at module level ──
const CHEAT_PROCESS_BASES: string[] = (() => {
  const names = new Set<string>()
  for (const p of KNOWN_PROCESSES) {
    const base = p.toLowerCase().replace(/\.exe$/i, '').replace(/_\\*\.exe$/i, '').replace(/\\*\.exe$/i, '')
    if (base.length >= 3) names.add(stripNonAlpha(base))
  }
  for (const f of KNOWN_CHEAT_FILES) {
    const base = f.toLowerCase().replace(/\.(dll|exe|asi|lua)$/i, '')
    if (base.length >= 3) names.add(stripNonAlpha(base))
  }
  const extras = [
    'eulen', 'redengine', 'skript', 'impulse', 'luna', 'paragon', 'ozark',
    'cherax', 'stand', '2take1', 'modest', 'kiddions', 'susano', 'lambda',
    'vmenu', 'nightfall', 'aurora', 'hydrogen', 'oxide', 'havoc', 'revolution',
    'cheatengine', 'xenos', 'extremeinjector', 'manualmap',
    'pcileech', 'fuser', 'screamer', 'kdmapper', 'drvmap',
    'ragemp', 'altv', 'cef', 'serverexecutor',
  ]
  for (const e of extras) names.add(stripNonAlpha(e))
  return Array.from(names)
})()

// Also keep original-names list for exact matching (registry, MuiCache, etc.)
const CHEAT_PROCESS_NAMES: string[] = (() => {
  const names = new Set<string>()
  for (const p of KNOWN_PROCESSES) {
    const base = p.toLowerCase().replace(/\.exe$/i, '')
    if (base.length >= 3) names.add(base)
  }
  for (const f of KNOWN_CHEAT_FILES) {
    const base = f.toLowerCase().replace(/\.(dll|exe|asi|lua)$/i, '')
    if (base.length >= 3) names.add(base)
  }
  return Array.from(names)
})()

// ══════════════════════════════════════════════════════════
// 1. PREFETCH SCAN
// ══════════════════════════════════════════════════════════

export function scanDeepPrefetch(): ScanResult[] {
  const results: ScanResult[] = []
  const prefetchDir = path.join(_WR, 'Prefetch')
  if (!fs.existsSync(prefetchDir)) return results

  try {
    for (const file of fs.readdirSync(prefetchDir)) {
      if (!file.toLowerCase().endsWith('.pf')) continue
      const fileStripped = stripNonAlpha(file.toLowerCase().replace(/\.pf$/i, ''))
      const execName = file.replace(/\.pf$/i, '')

      for (const base of CHEAT_PROCESS_BASES) {
        if (fileStripped.includes(base)) {
          const filePath = path.join(prefetchDir, file)
          let mtime = new Date().toISOString()
          let size = 0
          try {
            const stat = fs.statSync(filePath)
            mtime = stat.mtime.toISOString()
            size = stat.size
          } catch (err) { console.warn('[forensic-traces] failed:', (err as Error).message) }

          const dedupKey = `forensic-pf:${file}`
          if (addFindingDedup(dedupKey)) {
            const ageDays = ((Date.now() - new Date(mtime).getTime()) / 86400000).toFixed(0)
            results.push({
              path: filePath,
              fileName: `🧬 Prefetch: ${execName}`,
              type: 'file',
              risk: 'high',
              matches: [
                `prefetch:${execName}`,
                `matched:${base}`,
                `last-exec:${mtime.slice(0, 10)} (${ageDays}d ago)`,
                `⚠ CHEAT WAS EXECUTED — Prefetch survives file deletion`,
              ],
              size,
              modifiedAt: mtime,
            })
          }
          break
        }
      }
    }
  } catch (err) { console.warn('[forensic-traces] failed:', (err as Error).message) }

  return results
}

// ══════════════════════════════════════════════════════════
// 2. AMCACHE SCAN
// ══════════════════════════════════════════════════════════

export function scanAmcache(): ScanResult[] {
  const results: ScanResult[] = []
  const amcachePath = path.join(_WR, 'AppCompat', 'Programs', 'Amcache.hve')
  if (!fs.existsSync(amcachePath)) return results

  // Use reg.exe load/unload (safer than PowerShell for this)
  try {
    execSync('reg load HKLM\\Amcache_Temp "' + amcachePath + '" 2>nul', {
      encoding: 'utf-8',
      timeout: 8000,
      windowsHide: true,
    })
  } catch {
    return results // Can't load hive (maybe already loaded or permission denied)
  }

  try {
    // Query the File key for entries
    const out = regQuery('HKLM\\Amcache_Temp\\Root\\File', 12000)
    if (out) {
      const lower = out.toLowerCase()
      for (const base of CHEAT_PROCESS_NAMES) {
        if (lower.includes(base)) {
          const dedupKey = `forensic-amcache:${base}`
          if (addFindingDedup(dedupKey)) {
            results.push({
              path: 'Amcache.hve',
              fileName: `🧬 Amcache Evidence: ${base}`,
              type: 'system',
              risk: 'high',
              matches: [
                `amcache:${base}`,
                `⚠ Amcache persists FOREVER — proof of past installation`,
              ],
              size: 0,
              modifiedAt: new Date().toISOString(),
            })
          }
        }
      }
    }
  } catch { /* Amcache parsing optional */ }

  // ALWAYS unload the hive
  try {
    execSync('reg unload HKLM\\Amcache_Temp 2>nul', {
      encoding: 'utf-8',
      timeout: 5000,
      windowsHide: true,
    })
  } catch { /* best effort */ }

  return results
}

// ══════════════════════════════════════════════════════════
// 3. BAM SCAN (Background Activity Moderator)
// ══════════════════════════════════════════════════════════

export function scanBamKey(): ScanResult[] {
  const results: ScanResult[] = []
  const bamBase = 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\state\\UserSettings'

  try {
    const sidOutput = regQuery(bamBase, 3000)
    if (!sidOutput) return results

    const sidMatch = sidOutput.match(/S-1-5-21-[\d-]+/g)
    const sids = sidMatch ? [...new Set(sidMatch)] : []

    for (const sid of sids.slice(0, 5)) {
      const keyPath = `${bamBase}\\${sid}`
      const userBam = regQuery(keyPath, 5000)
      if (!userBam) continue

      const lower = userBam.toLowerCase()
      for (const base of CHEAT_PROCESS_NAMES) {
        if (lower.includes(base)) {
          const dedupKey = `forensic-bam:${sid}:${base}`
          if (addFindingDedup(dedupKey)) {
            results.push({
              path: keyPath,
              fileName: `🧬 BAM Entry: ${base}.exe`,
              type: 'registry',
              risk: 'high',
              matches: [
                `bam:${base}`,
                `⚠ BAM tracks all program executions — survives deletion`,
              ],
              size: 0,
              modifiedAt: new Date().toISOString(),
            })
          }
        }
      }
    }
  } catch { /* BAM optional */ }

  return results
}

// ══════════════════════════════════════════════════════════
// 4. USERASSIST SCAN (ROT13 encoded GUI execution history)
// ══════════════════════════════════════════════════════════

export function scanUserAssist(): ScanResult[] {
  const results: ScanResult[] = []
  const uaBase = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist'

  try {
    const guidList = regQuery(uaBase, 3000)
    if (!guidList) return results

    const guids = guidList.match(/\{[A-F0-9-]+\}/gi) || []

    for (const guid of guids.slice(0, 3)) {
      const countKey = `${uaBase}\\${guid}\\Count`
      const countData = regQuery(countKey, 5000)
      if (!countData) continue

      const lines = countData.split('\n')
      for (const line of lines) {
        const match = line.match(/^\s{4}(.+?)\s+REG_BINARY/)
        if (!match) continue

        const encoded = match[1].trim()
        const decoded = rot13(encoded).toLowerCase()

        for (const base of CHEAT_PROCESS_NAMES) {
          if (decoded.includes(base)) {
            const dedupKey = `forensic-ua:${base}`
            if (addFindingDedup(dedupKey)) {
              results.push({
                path: countKey,
                fileName: `🧬 UserAssist: ${decoded}`,
                type: 'registry',
                risk: 'high',
                matches: [
                  `userassist:${decoded}`,
                  `matched:${base}`,
                  `⚠ GUI program was launched by user — survives deletion`,
                ],
                size: 0,
                modifiedAt: new Date().toISOString(),
              })
            }
            break
          }
        }
      }
    }
  } catch { /* UserAssist optional */ }

  return results
}

// ══════════════════════════════════════════════════════════
// 5. MUICACHE SCAN
// ══════════════════════════════════════════════════════════

export function scanMuiCache(): ScanResult[] {
  const results: ScanResult[] = []
  const muiKey = 'HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache'

  try {
    const muiData = regQuery(muiKey, 5000)
    if (!muiData) return results

    const lower = muiData.toLowerCase()
    for (const base of CHEAT_PROCESS_NAMES) {
      if (lower.includes(base)) {
        const dedupKey = `forensic-mui:${base}`
        if (addFindingDedup(dedupKey)) {
          results.push({
            path: muiKey,
            fileName: `🧬 MuiCache: ${base}`,
            type: 'registry',
            risk: 'medium',
            matches: [
              `muicache:${base}`,
              `⚠ Application was present on this system`,
            ],
            size: 0,
            modifiedAt: new Date().toISOString(),
          })
        }
      }
    }
  } catch { /* MuiCache skip */ }

  return results
}

// ══════════════════════════════════════════════════════════
// 6. EVENT LOG SCAN — process creation (4688)
// NOTE: Requires Audit Process Creation to be enabled (not default on consumer Windows).
// ══════════════════════════════════════════════════════════

export function scanEventLogs(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    const out = ps(`
$ErrorActionPreference = 'SilentlyContinue'
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} -MaxEvents 300 -ErrorAction SilentlyContinue |
  Select-Object TimeCreated,
    @{N='Proc';E={$_.Properties[5].Value}},
    @{N='Cmd';E={$_.Properties[8].Value}} |
  Where-Object { $_.Proc } |
  Select-Object -First 100 |
  ConvertTo-Json -Compress
`, 15000)

    if (out && out.length > 5) {
      try {
        const events: { TimeCreated?: string; Proc?: string; Cmd?: string }[] = JSON.parse(out)
        const items = Array.isArray(events) ? events : [events]

        for (const evt of items.slice(0, 100)) {
          const procName = (evt.Proc || '').toLowerCase()
          const cmdLine = (evt.Cmd || '').toLowerCase()
          if (!procName) continue

          for (const base of CHEAT_PROCESS_NAMES) {
            if (procName.includes(base) || cmdLine.includes(base)) {
              const dedupKey = `forensic-evlog:${base}:${evt.TimeCreated || ''}`
              if (addFindingDedup(dedupKey)) {
                results.push({
                  path: 'Windows Security Event Log',
                  fileName: `🧬 Event 4688: ${evt.Proc || base}`,
                  type: 'system',
                  risk: 'high',
                  matches: [
                    `eventlog-4688:${evt.Proc || base}`,
                    `cmdline:${evt.Cmd || 'N/A'}`,
                    `time:${evt.TimeCreated || 'N/A'}`,
                    `⚠ Process creation logged by Windows Audit`,
                  ],
                  size: 0,
                  modifiedAt: evt.TimeCreated || new Date().toISOString(),
                })
              }
              break
            }
          }
        }
      } catch { /* parsing failed */ }
    }
  } catch { /* Event log optional */ }

  return results
}

// ══════════════════════════════════════════════════════════
// COMBINED FORENSIC SCAN
// ══════════════════════════════════════════════════════════

export function runForensicScan(): ScanResult[] {
  const results: ScanResult[] = []

  results.push(...scanDeepPrefetch())
  results.push(...scanBamKey())
  results.push(...scanUserAssist())
  results.push(...scanMuiCache())
  results.push(...scanAmcache())
  results.push(...scanEventLogs())

  return results
}
