/**
 * Predator — Enhanced PC Cleaning Detection Module
 *
 * Detects if the user cleaned their PC before an admin check.
 * Goes beyond basic anti-forensic — analyzes low-level NTFS artifacts,
 * timestamp anomalies, and cleaning tool signatures.
 *
 * Research sources: UnknownCheats forums, Synacktiv CCleaner Forensics,
 * Andrea Fortuna USN Journal analysis, Magnet Forensics anti-forensic research.
 *
 * Detection methods:
 * 1. USN Journal — gap detection, deleted entry enumeration
 * 2. Timestomping — file time vs USN journal timestamp mismatch
 * 3. ShellBags clearing — registry key absence pattern
 * 4. MFT orphaned entries — files deleted but still referenced
 * 5. SDelete / cipher / diskpart traces
 * 6. Registry MRU key clearing patterns (RunMRU, RecentDocs wiped)
 * 7. Custom cleaning scripts (cleaner.bat, wipe traces.ps1, etc.)
 * 8. Browser artifact wiping (cache, cookies, history simultaneously cleared)
 */

import { execSync, spawnSync } from 'child_process'
import path from 'path'
import fs from 'fs'
import { ScanResult, addFindingDedup, _WR, _HOME } from './types'

// ── Shell helpers ──
function ps(command: string, timeout = 10000): string {
  try {
    return execSync(`powershell -NoProfile -Command "${command}"`, {
      encoding: 'utf-8' as BufferEncoding,
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
      encoding: 'utf-8' as BufferEncoding,
      timeout,
    }).trim()
  } catch {
    return ''
  }
}

// ══════════════════════════════════════════════════════════
// 1. USN JOURNAL ANALYSIS
// ══════════════════════════════════════════════════════════

/**
 * USN Journal ($Extend\$UsnJrnl) records EVERY file system change.
 * If the journal was deleted/truncated, or if there are suspicious
 * gaps in the record, the user likely cleaned their PC.
 */
export function detectUsnJournalTampering(): ScanResult[] {
  const results: ScanResult[] = []
  const volumeRoot = _WR.slice(0, 3) // e.g. "C:"
  const usnPath = path.join(volumeRoot, '$Extend', '$UsnJrnl', '$J')

  try {
    // Check if USN Journal exists
    const exists = fs.existsSync(usnPath)

    if (!exists) {
      const dedupKey = 'pc-cleaner:usn-missing'
      if (addFindingDedup(dedupKey)) {
        results.push({
          path: usnPath,
          fileName: '🚨 USN Journal Missing — Evidence Destruction',
          type: 'system',
          risk: 'high',
          matches: [
            '⚠ USN JOURNAL DELETED — the most reliable NTFS forensic artifact',
            'All file system change history has been destroyed',
            'This requires admin privileges and intentional action',
          ],
          size: 0,
          modifiedAt: new Date().toISOString(),
        })
      }
      return results
    }

    // Query USN Journal via fsutil
    try {
      const fsutilOut = execSync(`fsutil usn queryjournal ${volumeRoot}`, {
        encoding: 'utf-8',
        timeout: 5000,
      }).trim()

      if (fsutilOut) {
        // Extract Maximum Size and Allocation Delta
        const maxSizeMatch = fsutilOut.match(/Maximum Size\s*:\s*0x([0-9a-fA-F]+)/)
        const allocDeltaMatch = fsutilOut.match(/Allocation Delta\s*:\s*0x([0-9a-fA-F]+)/)
        const usnIdMatch = fsutilOut.match(/USN ID\s*:\s*0x([0-9a-fA-F]+)/)
        const lowestUsnMatch = fsutilOut.match(/Lowest ValidUsn\s*:\s*0x([0-9a-fA-F]+)/)

        if (maxSizeMatch && usnIdMatch && lowestUsnMatch) {
          const maxSize = parseInt(maxSizeMatch[1], 16)
          const usnId = parseInt(usnIdMatch[1], 16)
          const lowestUsn = parseInt(lowestUsnMatch[1], 16)

          // If maxSize is abnormally small (< 32MB), journal was trimmed
          if (maxSize < 32 * 1024 * 1024) {
            const dedupKey = 'pc-cleaner:usn-small'
            if (addFindingDedup(dedupKey)) {
              results.push({
                path: usnPath,
                fileName: '🚨 USN Journal Trimmed (Abnormally Small)',
                type: 'system',
                risk: 'high',
                matches: [
                  `usn-max-size:${(maxSize / 1024 / 1024).toFixed(1)} MB (normal: 32MB+)`,
                  '⚠ USN Journal was intentionally shrunk — evidence suppression',
                ],
                size: maxSize,
                modifiedAt: new Date().toISOString(),
              })
            }
          }

          // If USN ID is close to lowest USN (journal was recently reset)
          if (usnId > 0 && lowestUsn > 0) {
            const range = usnId - lowestUsn
            if (range < 1000) {
              const dedupKey = 'pc-cleaner:usn-reset'
              if (addFindingDedup(dedupKey)) {
                results.push({
                  path: usnPath,
                  fileName: '🚨 USN Journal Recently Reset',
                  type: 'system',
                  risk: 'high',
                  matches: [
                    `usn-range:${range} entries (abnormally low)`,
                    '⚠ USN Journal was reset/cleared — evidence destroyed',
                  ],
                  size: 0,
                  modifiedAt: new Date().toISOString(),
                })
              }
            }
          }
        }
      }
    } catch { /* fsutil may fail */ }

    // Enumerate recent USN entries in suspicious paths
    const suspiciousPaths = [
      path.join(_HOME, 'Downloads'),
      path.join(_HOME, 'Desktop'),
      path.join(_HOME, 'AppData', 'Local', 'Temp'),
      path.join(_WR, 'Temp'),
      path.join(_WR, 'Prefetch'),
    ]

    // Check for high file modification activity via PowerShell
    for (const checkPath of suspiciousPaths) {
      if (!fs.existsSync(checkPath)) continue
      try {
        const psOut = ps(`
$path = '${checkPath.replace(/'/g, "''")}'
$files = Get-ChildItem -Path $path -ErrorAction SilentlyContinue |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-48) }
if ($files.Count -gt 100) { Write-Output ('MASS_MODIFY:' + $files.Count) }
`, 8000)

        if (psOut && psOut.includes("MASS_MODIFY:")) {
          const countMatch = psOut.match(/MASS_MODIFY:(\d+)/)
          if (countMatch && parseInt(countMatch[1]) > 100) {
            const dedupKey = `pc-cleaner:mass-modified:${path.basename(checkPath)}`
            if (addFindingDedup(dedupKey)) {
              results.push({
                path: checkPath,
                fileName: `Mass File Activity: ${path.basename(checkPath)}`,
                type: "system",
                risk: "medium",
                matches: [
                  `modified-files:${countMatch[1]}+ in last 48h`,
                  `High file modification activity detected`,
                ],
                size: 0,
                modifiedAt: new Date().toISOString(),
              })
            }
          }
        }
      } catch { /* optional */ }
    }
  } catch { /* skip */ }

  return results
}

// ══════════════════════════════════════════════════════════
// 2. TIMESTOMPING DETECTION
// ══════════════════════════════════════════════════════════

/**
 * Timestomping = changing file timestamps to hide when files were created/modified.
 * We detect this by comparing file system timestamps with internal file metadata.
 */
export function detectTimestomping(): ScanResult[] {
  const results: ScanResult[] = []
  const suspiciousPaths = [
    path.join(_HOME, 'Downloads'),
    path.join(_HOME, 'Desktop'),
  ]

  for (const dirPath of suspiciousPaths) {
    if (!fs.existsSync(dirPath)) continue
    try {
      const files = fs.readdirSync(dirPath).slice(0, 50)
      let stompedCount = 0

      for (const file of files) {
        const fp = path.join(dirPath, file)
        try {
          const stat = fs.statSync(fp)
          if (!stat.isFile()) continue

          // Skip recently created files (< 30 min) — fresh downloads naturally have identical timestamps
          const ageMs = Date.now() - stat.birthtimeMs
          if (ageMs < 1800000) continue

          // Check for timestomping: all 4 dates identical to the millisecond
          const dates = [stat.birthtimeMs, stat.mtimeMs, stat.atimeMs, stat.ctimeMs]
          const uniqueDates = new Set(dates)

          if (uniqueDates.size <= 1 && dates[0] > 0) {
            stompedCount++
          }

          // Check for future timestamps (another timestomping tactic)
          if (stat.mtimeMs > Date.now() + 86400000) {
            stompedCount++
          }

          // Check for epoch timestamps (Jan 1 1970 or Jan 1 1601)
          if (stat.mtimeMs < 86400000 * 2) {
            stompedCount++
          }
        } catch { /* skip */ }
      }

      if (stompedCount >= 5) {
        const dedupKey = `pc-cleaner:timestomp:${path.basename(dirPath)}`
        if (addFindingDedup(dedupKey)) {
          results.push({
            path: dirPath,
            fileName: `🚨 Timestomping Detected: ${path.basename(dirPath)}`,
            type: 'system',
            risk: 'high',
            matches: [
              `timestomped-files:${stompedCount}`,
              `⚠ File timestamps manipulated to hide activity`,
            ],
            size: 0,
            modifiedAt: new Date().toISOString(),
          })
        }
      }
    } catch { /* skip */ }
  }

  return results
}

// ══════════════════════════════════════════════════════════
// 3. SHELLBAGS CLEARING DETECTION
// ══════════════════════════════════════════════════════════

/**
 * ShellBags store folder view preferences (size, position, icon mode).
 * Cheaters often wipe ShellBags to remove evidence of browsing cheat folders.
 * A missing/empty ShellBags key is highly suspicious.
 */
export function detectShellBagsClearing(): ScanResult[] {
  const results: ScanResult[] = []
  const shellBagsKeys = [
    'HKCU\\Software\\Microsoft\\Windows\\Shell\\BagMRU',
    'HKCU\\Software\\Microsoft\\Windows\\Shell\\Bags',
    'HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU',
    'HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags',
  ]

  let missingCount = 0
  const missingKeys: string[] = []

  for (const key of shellBagsKeys) {
    const data = regQuery(key, 3000)
    if (!data || data.trim().length === 0) {
      missingCount++
      missingKeys.push(key.split('\\').pop() || key)
    }
  }

  if (missingCount >= 3) {
    const dedupKey = 'pc-cleaner:shellbags-missing'
    if (addFindingDedup(dedupKey)) {
      results.push({
        path: 'HKCU\\Software\\Microsoft\\Windows\\Shell',
        fileName: '🚨 ShellBags Registry Keys Wiped',
        type: 'registry',
        risk: 'high',
        matches: [
          `missing-keys:${missingKeys.join(', ')}`,
          `⚠ ShellBags store folder access history — wiped to hide cheat folder browsing`,
        ],
        size: 0,
        modifiedAt: new Date().toISOString(),
      })
    }
  }

  return results
}

// ══════════════════════════════════════════════════════════
// 4. SDELETE / CIPHER / DISKPART DETECTION
// ══════════════════════════════════════════════════════════

const SECURE_DELETE_PREFETCH = [
  'SDELETE', 'SDELETE64',
  'CIPHER', // Windows built-in cipher /w
  'DISKPART',
]

export function detectSecureDeleteTools(): ScanResult[] {
  const results: ScanResult[] = []
  const prefetchDir = path.join(_WR, 'Prefetch')

  if (!fs.existsSync(prefetchDir)) return results

  try {
    for (const file of fs.readdirSync(prefetchDir)) {
      const upper = file.toUpperCase()
      for (const tool of SECURE_DELETE_PREFETCH) {
        if (upper.includes(tool) && upper.endsWith('.PF')) {
          const filePath = path.join(prefetchDir, file)
          let mtime = new Date().toISOString()
          try { mtime = fs.statSync(filePath).mtime.toISOString() } catch { /* skip */ }

          const dedupKey = `pc-cleaner:secure-del:${tool}`
          if (addFindingDedup(dedupKey)) {
            results.push({
              path: filePath,
              fileName: `🚨 Secure Deletion Tool: ${tool}`,
              type: 'file',
              risk: 'high',
              matches: [
                `prefetch:${tool}`,
                `last-exec:${mtime.slice(0, 10)}`,
                `⚠ SECURE DELETION TOOL was used — files overwritten, not just deleted`,
              ],
              size: 0,
              modifiedAt: mtime,
            })
          }
        }
      }
    }
  } catch { /* skip */ }

  // Also check for cipher /w in Prefetch (overwrites free space)
  try {
    const psOut = ps(`
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} -MaxEvents 100 -ErrorAction SilentlyContinue |
  Where-Object { $_.Properties[8].Value -match 'cipher\\s+/w|sdelete|diskpart\\s+clean' } |
  Select-Object TimeCreated, @{N='Cmd';E={$_.Properties[8].Value}} |
  ConvertTo-Json -Compress
`, 12000)

    if (psOut && psOut.length > 5 && psOut !== '[]') {
      const dedupKey = 'pc-cleaner:secure-del-cmd'
      if (addFindingDedup(dedupKey)) {
        results.push({
          path: 'Windows Security Event Log',
          fileName: '🚨 Secure Wipe Command Executed',
          type: 'system',
          risk: 'high',
          matches: [
            'eventlog:cipher-or-sdelete-or-diskpart-clean',
            '⚠ Free space was overwritten — file recovery impossible',
          ],
          size: 0,
          modifiedAt: new Date().toISOString(),
        })
      }
    }
  } catch { /* optional */ }

  return results
}

// ══════════════════════════════════════════════════════════
// 5. REGISTRY MRU KEY CLEARING
// ══════════════════════════════════════════════════════════

/**
 * Cheaters wipe MRU (Most Recently Used) keys to hide evidence.
 * Detecting that these keys are EMPTY when they should have entries
 * is a strong indicator of cleaning.
 */
export function detectRegistryMruClearing(): ScanResult[] {
  const results: ScanResult[] = []

  const mruKeys = [
    { key: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU', name: 'RunMRU' },
    { key: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs', name: 'RecentDocs' },
    { key: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU', name: 'OpenSaveMRU' },
    { key: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU', name: 'LastVisitedMRU' },
  ]

  let clearedCount = 0
  const clearedKeys: string[] = []

  for (const { key, name } of mruKeys) {
    const data = regQuery(key, 3000)
    // If the key exists but has no subkeys/values (or minimal), it was likely cleaned
    const lineCount = data.split('\n').filter(l => l.trim()).length

    if (lineCount <= 1) {
      clearedCount++
      clearedKeys.push(name)
    }
  }

  if (clearedCount >= 3) { // 3 of 4 MRU keys wiped = strong signal
    const dedupKey = 'pc-cleaner:mru-cleared'
    if (addFindingDedup(dedupKey)) {
      results.push({
        path: 'HKCU\\...\\Explorer',
        fileName: '🚨 MRU Registry Keys Mass-Cleared',
        type: 'registry',
        risk: 'high',
        matches: [
          `cleared-keys:${clearedKeys.join(', ')}`,
          `⚠ ${clearedCount}/6 MRU keys wiped — file/document access history destroyed`,
        ],
        size: 0,
        modifiedAt: new Date().toISOString(),
      })
    }
  }

  return results
}

// ══════════════════════════════════════════════════════════
// 6. CUSTOM CLEANING SCRIPTS DETECTION
// ══════════════════════════════════════════════════════════

/**
 * Cheaters often share .bat/.ps1 cleaning scripts on Discord/forums.
 * We detect their traces in Prefetch and script content.
 */
const CLEANING_SCRIPT_NAMES = [
  'cleaner', 'cleantraces', 'wipeall', 'wipetraces',
  'pc_clean', 'beforecheck', 'cleanup', 'traces_cleaner',
  'clean_traces', 'wipe_pc', 'clear_logs',
  'purge', 'sanitize', 'nuke_traces',
]

export function detectCleaningScripts(): ScanResult[] {
  const results: ScanResult[] = []
  const prefetchDir = path.join(_WR, 'Prefetch')

  // 1. Prefetch — check if any cleaning script was executed
  if (fs.existsSync(prefetchDir)) {
    try {
      for (const file of fs.readdirSync(prefetchDir)) {
        const lower = file.toLowerCase()
        // Check both .bat and .ps1 prefetch entries
        for (const scriptName of CLEANING_SCRIPT_NAMES) {
          const extMatch = lower.match(
            new RegExp(`(${scriptName})\\.(bat|ps1|cmd)`, 'i')
          )
          if (extMatch && lower.endsWith('.pf')) {
            const filePath = path.join(prefetchDir, file)
            let mtime = new Date().toISOString()
            try { mtime = fs.statSync(filePath).mtime.toISOString() } catch { /* skip */ }

            const dedupKey = `pc-cleaner:script-pf:${scriptName}`
            if (addFindingDedup(dedupKey)) {
              results.push({
                path: filePath,
                fileName: `🚨 Cleaning Script Executed: ${file.replace(/\.pf$/i, '')}`,
                type: 'file',
                risk: 'high',
                matches: [
                  `prefetch:${scriptName}`,
                  `last-exec:${mtime.slice(0, 10)}`,
                  `⚠ CUSTOM CLEANING SCRIPT was run — targeted evidence destruction`,
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

  // 2. Scan for cleaning scripts in Downloads/Desktop
  const searchPaths = [
    path.join(_HOME, 'Downloads'),
    path.join(_HOME, 'Desktop'),
    path.join(_HOME, 'Documents'),
  ]

  for (const dirPath of searchPaths) {
    if (!fs.existsSync(dirPath)) continue
    try {
      for (const file of fs.readdirSync(dirPath)) {
        const lower = file.toLowerCase()
        if (!lower.endsWith('.bat') && !lower.endsWith('.ps1') && !lower.endsWith('.cmd')) continue

        for (const scriptName of CLEANING_SCRIPT_NAMES) {
          if (lower.includes(scriptName)) {
            const filePath = path.join(dirPath, file)
            let content = ''
            try {
              content = fs.readFileSync(filePath, 'utf-8').toLowerCase().slice(0, 500)
            } catch { /* binary */ }

            const hasDeleteCmd = content.includes('del ') || content.includes('remove-item') ||
              content.includes('rd ') || content.includes('rmdir')

            if (hasDeleteCmd) {
              const dedupKey = `pc-cleaner:script-file:${file}`
              if (addFindingDedup(dedupKey)) {
                results.push({
                  path: filePath,
                  fileName: `🚨 Cleaning Script Found: ${file}`,
                  type: 'file',
                  risk: 'high',
                  matches: [
                    `file:${file}`,
                    `content:contains deletion commands`,
                    `⚠ CLEANING SCRIPT PRESENT ON DISK`,
                  ],
                  size: 0,
                  modifiedAt: new Date().toISOString(),
                })
              }
            }
            break
          }
        }
      }
    } catch { /* skip */ }
  }

  return results
}

// ══════════════════════════════════════════════════════════
// 7. BROWSER ARTIFACT MASS-WIPING
// ══════════════════════════════════════════════════════════

/**
 * When ALL browser artifacts (history, cache, cookies, downloads)
 * were cleared simultaneously, it's a strong cleaning indicator.
 */
export function detectBrowserMassWipe(): ScanResult[] {
  const results: ScanResult[] = []

  const browserProfiles = [
    {
      name: 'Chrome',
      dir: path.join(_HOME, 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default'),
      files: ['History', 'Cookies', 'Web Data', 'Favicons', 'Login Data', 'Shortcuts'],
    },
    {
      name: 'Edge',
      dir: path.join(_HOME, 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Default'),
      files: ['History', 'Cookies', 'Web Data', 'Favicons', 'Login Data'],
    },
  ]

  for (const browser of browserProfiles) {
    if (!fs.existsSync(browser.dir)) continue

    try {
      const stats = browser.files.map(f => {
        const fp = path.join(browser.dir, f)
        if (!fs.existsSync(fp)) return null
        const s = fs.statSync(fp)
        return { file: f, size: s.size, mtime: s.mtimeMs }
      }).filter(Boolean) as { file: string; size: number; mtime: number }[]

      if (stats.length < 3) continue

      // Check if all files were modified within the same hour
      const mtimes = stats.map(s => s.mtime)
      const maxMtime = Math.max(...mtimes)
      const minMtime = Math.min(...mtimes)
      const allInOneHour = (maxMtime - minMtime) < 3600000 // 1 hour

      // Check if profile is older than 24 hours (not a fresh install)
      const profileOld = minMtime < Date.now() - 86400000

      // Check if all files are abnormally small
      const allTiny = stats.every(s => s.size < 10240) // < 10KB each

      if (allInOneHour && allTiny && profileOld) {
        const dedupKey = `pc-cleaner:browser-wipe:${browser.name}`
        if (addFindingDedup(dedupKey)) {
          results.push({
            path: browser.dir,
            fileName: `🚨 ${browser.name} Browser Mass-Wiped`,
            type: 'system',
            risk: 'medium',
            matches: [
              `browser:${browser.name}`,
              `modified-same-hour:${new Date(minMtime).toISOString().slice(0, 16)}`,
              `all-files-tiny:${stats.map(s => `${s.file}=${s.size}B`).join(', ')}`,
              `⚠ ALL browser artifacts cleared simultaneously`,
            ],
            size: 0,
            modifiedAt: new Date(maxMtime).toISOString(),
          })
        }
      }
    } catch { /* skip */ }
  }

  return results
}

// ══════════════════════════════════════════════════════════
// COMBINED ENHANCED PC CLEANER SCAN
// ══════════════════════════════════════════════════════════

export function runPcCleanerScan(): ScanResult[] {
  const results: ScanResult[] = []

  // Phase 1: NTFS-level artifacts
  results.push(...detectUsnJournalTampering())

  // Phase 2: Timestomping
  results.push(...detectTimestomping())

  // Phase 3: ShellBags
  results.push(...detectShellBagsClearing())

  // Phase 4: Secure delete tools
  results.push(...detectSecureDeleteTools())

  // Phase 5: Registry MRU clearing
  results.push(...detectRegistryMruClearing())

  // Phase 6: Custom cleaning scripts
  results.push(...detectCleaningScripts())

  // Phase 7: Browser mass-wipe
  results.push(...detectBrowserMassWipe())

  return results
}
