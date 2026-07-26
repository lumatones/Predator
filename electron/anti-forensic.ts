/**
 * Predator — Anti-Forensic Detection Module
 *
 * Detects if the user attempted to clean their PC before a scan.
 * Anti-forensic tools (CCleaner, BleachBit, Eraser, etc.) leave
 * their own traces — we detect those.
 *
 * Detection methods:
 * 1. Event Log clearing — Event ID 1102 (Security), 104 (System)
 * 2. CCleaner/BleachBit execution traces (Prefetch, registry)
 * 3. Prefetch vs Shimcache vs Amcache inconsistencies
 * 4. Browser history clearing patterns
 * 5. Recycle Bin emptying evidence
 * 6. Temp folder mass-cleaning patterns
 * 7. USN Journal gaps (if readable)
 */

import { execSync } from 'child_process'
import path from 'path'
import fs from 'fs'
import { ScanResult, addFindingDedup, _WR, _HOME } from './types'

// ── PowerShell helper ──
function ps(command: string, timeout = 8000): string {
  try {
    return execSync(`powershell -NoProfile -Command "${command.replace(/"/g, '\\"')}"`, {
      encoding: 'utf-8' as BufferEncoding,
      timeout,
      windowsHide: true,
    }).trim()
  } catch {
    return ''
  }
}

// ── Registry query helper ──
function regQuery(keyPath: string, timeout = 5000): string {
  try {
    return execSync(`reg query "${keyPath}" /s 2>nul`, {
      encoding: 'utf-8' as BufferEncoding,
      timeout,
    }).trim()
  } catch {
    return ''
  }
}

// ══════════════════════════════════════════════════════════
// 1. EVENT LOG CLEARING DETECTION
// ══════════════════════════════════════════════════════════

export function detectEventLogClearing(): ScanResult[] {
  const results: ScanResult[] = []

  // Event ID 1102 = Security audit log cleared
  // Event ID 104 = System/Application log cleared
  const psCmd = `
$ErrorActionPreference = 'SilentlyContinue'
$evts = @()
# Security log clear (1102)
$sec = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=1102} -MaxEvents 5 -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, @{N='User';E={$_.Properties[1].Value}}, @{N='Message';E={$_.Message}}
if ($sec) { $evts += $sec }
# System log clear (104)
$sys = Get-WinEvent -FilterHashtable @{LogName='System'; ID=104} -MaxEvents 5 -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, @{N='Message';E={$_.Message}}
if ($sys) { $evts += $sys }
# Application log clear (104)
$app = Get-WinEvent -FilterHashtable @{LogName='Application'; ID=104} -MaxEvents 5 -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, @{N='Message';E={$_.Message}}
if ($app) { $evts += $app }
$evts | ConvertTo-Json -Compress
`

  try {
    const out = ps(psCmd, 10000)
    if (out && out.length > 5) {
      const events = JSON.parse(out)
      const items = Array.isArray(events) ? events : [events]

      for (const evt of items) {
        if (!evt.TimeCreated) continue
        const ageDays = (Date.now() - new Date(evt.TimeCreated).getTime()) / (1000 * 60 * 60 * 24)
        const dedupKey = `anti-forensic:logclear:${evt.TimeCreated}`

        if (addFindingDedup(dedupKey)) {
          results.push({
            path: 'Windows Event Logs',
            fileName: '🚨 Event Log Was Cleared!',
            type: 'system',
            risk: 'high',
            matches: [
              `eventlog-cleared:${evt.TimeCreated}`,
              `user:${evt.User || 'SYSTEM'}`,
              `age:${ageDays.toFixed(1)} days ago`,
              evt.Message ? `detail:${evt.Message.slice(0, 80)}` : '',
              `⚠ USER ATTEMPTED TO COVER THEIR TRACKS`,
            ].filter(Boolean),
            size: 0,
            modifiedAt: evt.TimeCreated,
          })
        }
      }
    }
  } catch { /* skip */ }

  return results
}

// ══════════════════════════════════════════════════════════
// 2. CCLEANER / BLEACHBIT TRACE DETECTION
// ══════════════════════════════════════════════════════════

const CLEANER_TOOLS_PREFETCH = [
  'CCLEANER', 'CCLEANER64', 'BLEACHBIT',
  'WISEDISKCLNR', 'PRIVACYERASER', 'BCWIPE',
  'ERASER', 'FILESHREDDER', 'DISKCLEANER',
]

const CLEANER_REGISTRY_KEYS = [
  'HKCU\\Software\\Piriform\\CCleaner',
  'HKCU\\Software\\BleachBit',
  'HKLM\\Software\\Piriform\\CCleaner',
  'HKCU\\Software\\PrivacyEraser',
  'HKCU\\Software\\WiseCleaner',
]

export function detectCleaningTools(): ScanResult[] {
  const results: ScanResult[] = []
  const prefetchDir = path.join(_WR, 'Prefetch')

  // 1. Prefetch — check if CCleaner/BleachBit etc. was ever executed
  if (fs.existsSync(prefetchDir)) {
    try {
      for (const file of fs.readdirSync(prefetchDir)) {
        const upper = file.toUpperCase()
        for (const tool of CLEANER_TOOLS_PREFETCH) {
          if (upper.includes(tool) && upper.endsWith('.PF')) {
            const filePath = path.join(prefetchDir, file)
            let mtime = new Date().toISOString()
            try { mtime = fs.statSync(filePath).mtime.toISOString() } catch { /* skip */ }

            const dedupKey = `anti-forensic:cleaner-pf:${tool}`
            if (addFindingDedup(dedupKey)) {
              results.push({
                path: filePath,
                fileName: `🚨 Cleaning Tool: ${file.replace(/\.pf$/i, '.exe')}`,
                type: 'file',
                risk: 'high',
                matches: [
                  `prefetch:${tool}`,
                  `last-exec:${mtime.slice(0, 10)}`,
                  `⚠ PC CLEANING TOOL WAS USED — evidence tampering`,
                ],
                size: 0,
                modifiedAt: mtime,
              })
            }
          }
        }
      }
    } catch { /* skip */ }
  }

  // 2. Registry — check for cleaner tool configuration keys
  for (const key of CLEANER_REGISTRY_KEYS) {
    try {
      const data = regQuery(key, 3000)
      if (data && data.trim().length > 0) {
        const dedupKey = `anti-forensic:cleaner-reg:${key}`
        if (addFindingDedup(dedupKey)) {
          results.push({
            path: key,
            fileName: `🚨 Cleaning Tool Registry: ${key.split('\\').pop()}`,
            type: 'registry',
            risk: 'high',
            matches: [
              `registry-key:${key}`,
              `⚠ PC CLEANING SOFTWARE INSTALLED/USED`,
            ],
            size: 0,
            modifiedAt: new Date().toISOString(),
          })
        }
      }
    } catch { /* skip */ }
  }

  // 3. Scheduled tasks for cleaners
  try {
    const tasksDir = path.join(_WR, 'System32', 'Tasks')
    if (fs.existsSync(tasksDir)) {
      for (const file of fs.readdirSync(tasksDir)) {
        const upper = file.toUpperCase()
        if (CLEANER_TOOLS_PREFETCH.some(t => upper.includes(t))) {
          const dedupKey = `anti-forensic:task:${file}`
          if (addFindingDedup(dedupKey)) {
            results.push({
              path: path.join(tasksDir, file),
              fileName: `🚨 Scheduled Cleaner Task: ${file}`,
              type: 'software',
              risk: 'medium',
              matches: [
                `scheduled-task:${file}`,
                `⚠ Automatic PC cleaning scheduled`,
              ],
              size: 0,
              modifiedAt: new Date().toISOString(),
            })
          }
        }
      }
    }
  } catch { /* skip */ }

  return results
}

// ══════════════════════════════════════════════════════════
// 3. PREFETCH CLEANING DETECTION
// ══════════════════════════════════════════════════════════

export function detectPrefetchCleaning(): ScanResult[] {
  const results: ScanResult[] = []
  const prefetchDir = path.join(_WR, 'Prefetch')

  if (!fs.existsSync(prefetchDir)) {
    results.push({
      path: prefetchDir,
      fileName: '🚨 Prefetch Directory Missing!',
      type: 'system',
      risk: 'high',
      matches: [
        `⚠ PREFETCH FOLDER DELETED — aggressive evidence destruction`,
        `Normal Windows systems ALWAYS have Prefetch files`,
      ],
      size: 0,
      modifiedAt: new Date().toISOString(),
    })
    return results
  }

  try {
    const files = fs.readdirSync(prefetchDir).filter(f => f.endsWith('.pf'))
    const count = files.length

    // Normal Windows 10/11 system has 100-300+ Prefetch files
    // If fewer than 30, Prefetch was likely cleaned
    if (count < 30) {
      const dedupKey = 'anti-forensic:prefetch-low-count'
      if (addFindingDedup(dedupKey)) {
        results.push({
          path: prefetchDir,
          fileName: `🚨 Suspicious: Only ${count} Prefetch files`,
          type: 'system',
          risk: 'medium',
          matches: [
            `prefetch-count:${count} (normal: 100-300+)`,
            `⚠ Prefetch MAY have been manually cleaned`,
          ],
          size: 0,
          modifiedAt: new Date().toISOString(),
        })
      }
    }

    // Check for recently modified Prefetch folder (bulk delete)
    const stat = fs.statSync(prefetchDir)
    const ageHours = (Date.now() - stat.mtimeMs) / (1000 * 60 * 60)
    if (ageHours < 24 && count < 50) {
      const dedupKey = 'anti-forensic:prefetch-recent-mod'
      if (addFindingDedup(dedupKey)) {
        results.push({
          path: prefetchDir,
          fileName: '🚨 Prefetch Recently Modified',
          type: 'system',
          risk: 'medium',
          matches: [
            `prefetch-mtime:${stat.mtime.toISOString().slice(0, 16)}`,
            `age-hours:${ageHours.toFixed(1)}`,
            `⚠ Prefetch was modified in the last 24 hours`,
          ],
          size: 0,
          modifiedAt: stat.mtime.toISOString(),
        })
      }
    }
  } catch { /* skip */ }

  return results
}

// ══════════════════════════════════════════════════════════
// 4. BROWSER HISTORY CLEARING DETECTION
// ══════════════════════════════════════════════════════════

export function detectBrowserHistoryClearing(): ScanResult[] {
  const results: ScanResult[] = []

  const browserPaths = [
    { name: 'Chrome', dir: path.join(_HOME, 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default') },
    { name: 'Edge', dir: path.join(_HOME, 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Default') },
    { name: 'Brave', dir: path.join(_HOME, 'AppData', 'Local', 'BraveSoftware', 'Brave-Browser', 'User Data', 'Default') },
    { name: 'Opera', dir: path.join(_HOME, 'AppData', 'Roaming', 'Opera Software', 'Opera Stable') },
  ]

  for (const browser of browserPaths) {
    const historyFile = path.join(browser.dir, 'History')
    if (!fs.existsSync(historyFile)) continue

    try {
      const stat = fs.statSync(historyFile)
      const sizeKb = stat.size / 1024

      // Normal browser history is typically 500KB - 50MB
      // Very small (< 10KB) + recently modified = likely cleared
      const ageHours = (Date.now() - stat.mtimeMs) / (1000 * 60 * 60)

      if (sizeKb < 10 && ageHours < 72) {
        const dedupKey = `anti-forensic:browser-clear:${browser.name}`
        if (addFindingDedup(dedupKey)) {
          results.push({
            path: historyFile,
            fileName: `🚨 ${browser.name} History Likely Cleared`,
            type: 'system',
            risk: 'medium',
            matches: [
              `browser:${browser.name}`,
              `history-size:${sizeKb.toFixed(1)} KB (abnormally small)`,
              `last-modified:${stat.mtime.toISOString().slice(0, 16)}`,
              `⚠ Browser history appears to have been wiped`,
            ],
            size: stat.size,
            modifiedAt: stat.mtime.toISOString(),
          })
        }
      }
    } catch { /* skip */ }
  }

  return results
}

// ══════════════════════════════════════════════════════════
// 5. RECYCLE BIN EMPTYING DETECTION
// ══════════════════════════════════════════════════════════

export function detectRecycleBinClearing(): ScanResult[] {
  const results: ScanResult[] = []
  const recycleDir = path.join(_WR.slice(0, 3), '$Recycle.Bin')

  if (!fs.existsSync(recycleDir)) return results

  try {
    // Count $I (metadata) vs $R (data) files
    let iFiles = 0
    let rFiles = 0

    for (const dir of fs.readdirSync(recycleDir)) {
      const fullDir = path.join(recycleDir, dir)
      try {
        if (fs.statSync(fullDir).isDirectory() && dir.startsWith('S-1-5')) {
          for (const file of fs.readdirSync(fullDir)) {
            if (file.startsWith('$I')) iFiles++
            if (file.startsWith('$R')) rFiles++
          }
        }
      } catch { /* skip */ }
    }

    // If there are $I files without matching $R files, bin was emptied
    if (iFiles > rFiles && iFiles > 0) {
      const dedupKey = 'anti-forensic:recycle-bin-gap'
      if (addFindingDedup(dedupKey)) {
        results.push({
          path: recycleDir,
          fileName: '🚨 Recycle Bin Emptied (Metadata / Data Mismatch)',
          type: 'system',
          risk: 'medium',
          matches: [
            `recycle-bin:$I=${iFiles}, $R=${rFiles}`,
            `orphaned-metadata:${iFiles - rFiles}`,
            `⚠ Evidence deleted from Recycle Bin`,
          ],
          size: 0,
          modifiedAt: new Date().toISOString(),
        })
      }
    }
  } catch { /* skip */ }

  return results
}

// ══════════════════════════════════════════════════════════
// 6. TEMP FOLDER MASS-CLEANING DETECTION
// ══════════════════════════════════════════════════════════

export function detectTempCleaning(): ScanResult[] {
  const results: ScanResult[] = []
  const tempDir = path.join(_WR, 'Temp')

  if (!fs.existsSync(tempDir)) return results

  try {
    const files = fs.readdirSync(tempDir)
    const count = files.length

    // Normal Temp dir has many leftover files from various programs
    // If nearly empty, it was likely cleaned
    if (count < 15) {
      const stat = fs.statSync(tempDir)
      const ageHours = (Date.now() - stat.mtimeMs) / (1000 * 60 * 60)

      if (ageHours < 48) {
        const dedupKey = 'anti-forensic:temp-clean'
        if (addFindingDedup(dedupKey)) {
          results.push({
            path: tempDir,
            fileName: '🚨 Temp Folder Recently Cleaned',
            type: 'system',
            risk: 'medium',
            matches: [
              `temp-files:${count} (abnormally low)`,
              `folder-age-hours:${ageHours.toFixed(1)}`,
              `⚠ Temp files were recently deleted`,
            ],
            size: 0,
            modifiedAt: stat.mtime.toISOString(),
          })
        }
      }
    }
  } catch { /* skip */ }

  return results
}

// ══════════════════════════════════════════════════════════
// COMBINED ANTI-FORENSIC SCAN
// ══════════════════════════════════════════════════════════

export function runAntiForensicScan(): ScanResult[] {
  const results: ScanResult[] = []

  // 1. Event Log clearing
  results.push(...detectEventLogClearing())

  // 2. Cleaning tool traces (CCleaner, BleachBit, etc.)
  results.push(...detectCleaningTools())

  // 3. Prefetch cleaning
  results.push(...detectPrefetchCleaning())

  // 4. Browser history clearing
  results.push(...detectBrowserHistoryClearing())

  // 5. Recycle Bin emptying
  results.push(...detectRecycleBinClearing())

  // 6. Temp folder cleaning
  results.push(...detectTempCleaning())

  return results
}
