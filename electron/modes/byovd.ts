/**
 * Predator — BYOVD (Bring Your Own Vulnerable Driver) Scanner
 *
 * Scans for known vulnerable kernel drivers that cheaters exploit
 * to gain kernel-level R/W access for bypassing anti-cheat protection.
 *
 * Detection methods:
 *   - File existence in System32\drivers (check filename + signature)
 *   - Loaded driver services via WMI (Win32_SystemDriver)
 *   - Registry entries in HKLM\SYSTEM\CurrentControlSet\Services
 */

import { execSync } from 'child_process'
import * as fs from 'fs'
import * as path from 'path'
import { _WR, type ScanResult, addFindingDedup } from '../types'

// ═══════════════════════════════════════════════════
// KNOWN VULNERABLE DRIVERS DATABASE
// ═══════════════════════════════════════════════════

interface VulnerableDriver {
  /** Common file names used by this driver */
  fileNames: string[]
  /** Known service names */
  serviceNames: string[]
  /** Description of the vulnerability */
  description: string
  /** Real-world cheat tools that abuse this driver */
  abusedBy: string[]
}

const VULNERABLE_DRIVERS: VulnerableDriver[] = [
  {
    fileNames: ['gdrv.sys', 'gdrv3.sys'],
    serviceNames: ['gdrv', 'gdrv3'],
    description: 'GIGABYTE driver — arbitrary physical memory R/W',
    abusedBy: ['Process Hacker', 'EAC bypass loaders', 'kernel R/W tools'],
  },
  {
    fileNames: ['RTCore64.sys', 'RTCore32.sys'],
    serviceNames: ['RTCore64', 'RTCore32'],
    description: 'MSI Afterburner driver — arbitrary MSR write / kernel memory R/W',
    abusedBy: ['EAC bypass', 'BE bypass', 'Vanguard bypass loaders'],
  },
  {
    fileNames: ['Capcom.sys'],
    serviceNames: ['Capcom'],
    description: 'Capcom Anti-Cheat driver — insufficient access control allows kernel R/W',
    abusedBy: ['P2C (pay-to-cheat) frameworks', 'EFI bootkit loaders'],
  },
  {
    fileNames: ['kprocesshacker.sys', 'kprocesshacker2.sys', 'kprocesshacker3.sys'],
    serviceNames: ['kprocesshacker', 'kprocesshacker2', 'kprocesshacker3'],
    description: 'Process Hacker kernel driver — powerful system manipulation',
    abusedBy: ['Manual mappers', 'process killer tools', 'handle hijacking'],
  },
  {
    fileNames: ['winio64.sys', 'winio32.sys'],
    serviceNames: ['WinIO', 'winio64'],
    description: 'WinIO driver — port and memory I/O',
    abusedBy: ['Hardware communication tools', 'DMA card initialization'],
  },
  {
    fileNames: ['phymem.sys'],
    serviceNames: ['phymem', 'PhysicalMemory'],
    description: 'Physical Memory driver — raw physical memory access',
    abusedBy: ['Memory dump tools', 'kernel R/W scripts'],
  },
  {
    fileNames: ['dbk64.sys', 'dbk32.sys', 'dbkupd.exe'],
    serviceNames: ['DBK64', 'DBK32', 'dbkdrv'],
    description: 'Cheat Engine DBK driver — kernel-level memory access',
    abusedBy: ['Cheat Engine (kernel mode)', 'memory scanners'],
  },
  {
    fileNames: ['cpuz.sys', 'cpuz143.sys', 'cpuz150.sys'],
    serviceNames: ['cpuz143', 'cpuz150', 'cpuz'],
    description: 'CPU-Z driver — vulnerable IOCTL allows kernel R/W',
    abusedBy: ['Driver exploit chains', 'manual mappers'],
  },
  {
    fileNames: ['interception.sys'],
    serviceNames: ['interception'],
    description: 'Interception driver — kernel-level keyboard/mouse input hook',
    abusedBy: ['KMBox automation', 'hardware aimbot scripts', 'input injection tools'],
  },
]

// Additional drive-by detection: filenames commonly associated with BYOVD
const BYOVD_FILENAME_PATTERNS = [
  'kprocesshacker', 'winio', 'phymem', 'dbk', 'cpuz',
  'gdrv', 'rtcore', 'capcom', 'dump64',
]

// ═══════════════════════════════════════════════════
// SCANNING
// ═══════════════════════════════════════════════════

/**
 * Tier 1: Check file existence in System32\drivers + signature verification.
 * This catches drivers installed but not currently loaded.
 */
function scanByovdFiles(): ScanResult[] {
  const results: ScanResult[] = []
  const driversDir = path.join(_WR, 'System32', 'drivers')

  if (!fs.existsSync(driversDir)) return results

  try {
    const existingFiles = new Set(fs.readdirSync(driversDir).map(f => f.toLowerCase()))

    for (const vd of VULNERABLE_DRIVERS) {
      for (const fileName of vd.fileNames) {
        if (existingFiles.has(fileName.toLowerCase())) {
          if (addFindingDedup(`byovd-file:${fileName}`)) {
            results.push({
              path: `Hardware: BYOVD Driver File`,
              fileName: `⚠ Vulnerable Driver: ${fileName}`,
              type: 'hardware',
              risk: 'high',
              matches: [
                `Found: C:\\Windows\\System32\\drivers\\${fileName}`,
                `Vulnerability: ${vd.description}`,
                `Abused by: ${vd.abusedBy.join(', ')}`,
                `⚠ This driver grants kernel-level R/W access`,
                `⚠ Used by cheaters to bypass anti-cheat protection`,
              ],
              size: 0,
              modifiedAt: new Date().toISOString(),
            })
          }
          break // One finding per driver entry
        }
      }
    }

    // Broad scan: check for filenames matching BYOVD patterns
    for (const file of fs.readdirSync(driversDir)) {
      const lower = file.toLowerCase()
      const shouldCheck = BYOVD_FILENAME_PATTERNS.some(p => lower.includes(p))
      if (!shouldCheck || existingFiles.has(lower)) continue // Skip already matched

      // Only flag if file is NOT digitally signed by Microsoft
      // (legitimate drivers with these name patterns from MS are OK)
      try {
        const filePath = path.join(driversDir, file)
        const psScript = `(Get-AuthenticodeSignature '${filePath.replace(/'/g, "''")}').Status`
        const sigOut = execSync(`powershell -NoProfile -Command "${psScript}"`, {
          encoding: 'utf-8', timeout: 3000, windowsHide: true,
        }).trim()
        const isSigned = sigOut.includes('Valid')

        if (!isSigned && addFindingDedup(`byovd-pattern:${file}`)) {
          results.push({
            path: `Hardware: BYOVD Driver File`,
            fileName: `⚠ Suspicious Driver: ${file} (unsigned)`,
            type: 'hardware',
            risk: 'medium',
            matches: [
              `Found: C:\\Windows\\System32\\drivers\\${file}`,
              `Matches BYOVD filename pattern: "${BYOVD_FILENAME_PATTERNS.find(p => lower.includes(p)) || 'unknown'}"`,
              `Driver is NOT digitally signed`,
              `⚠ Unsigned kernel drivers are extremely suspicious`,
            ],
            size: 0,
            modifiedAt: new Date().toISOString(),
          })
        }
      } catch { /* sig check optional */ }
    }
  } catch { /* file scan optional */ }

  return results
}

/**
 * Tier 2: Check loaded driver services via WMI.
 * This catches drivers currently loaded and running in kernel space.
 */
function scanByovdServices(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    // Query loaded kernel drivers via WMI
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
$drivers = Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Running' } | Select-Object Name, DisplayName, PathName, State | ConvertTo-Json -Compress
if ($drivers) { $drivers } else { '[]' }
`
    const out = execSync(`powershell -NoProfile -Command "${psScript.replace(/"/g, '\\"')}"`, {
      encoding: 'utf-8', timeout: 8000, windowsHide: true,
    }).trim()

    if (!out || out === '[]' || out.length < 5) return results

    let driverList: { Name?: string; DisplayName?: string; PathName?: string; State?: string }[] = []
    try {
      driverList = JSON.parse(out)
      if (!Array.isArray(driverList)) driverList = [driverList]
    } catch { return results }

    const loadedNames = new Set(driverList.map(d => (d.Name || '').toLowerCase()))
    const loadedPaths = new Set(driverList.map(d => (d.PathName || '').toLowerCase()))

    for (const vd of VULNERABLE_DRIVERS) {
      // Check by service name
      const matchedService = vd.serviceNames.find(sn => loadedNames.has(sn.toLowerCase()))
      // Check by file path
      const matchedPath = vd.fileNames.find(fn => {
        for (const lp of loadedPaths) {
          if (lp.endsWith(fn.toLowerCase())) return true
        }
        return false
      })

      if (matchedService || matchedPath) {
        const key = `byovd-svc:${matchedService || matchedPath}`
        if (addFindingDedup(key)) {
          results.push({
            path: `Hardware: BYOVD Loaded Driver`,
            fileName: `⚠ ACTIVE Vulnerable Driver: ${matchedService || matchedPath}`,
            type: 'hardware',
            risk: 'high',
            matches: [
              `Status: LOADED AND RUNNING in kernel space`,
              `Vulnerability: ${vd.description}`,
              `Abused by: ${vd.abusedBy.join(', ')}`,
              `⚠ This driver is currently providing kernel-level access`,
              `⚠ Cheater may have active kernel R/W capabilities`,
            ],
            size: 0,
            modifiedAt: new Date().toISOString(),
          })
        }
        break
      }
    }
  } catch { /* WMI query optional */ }

  return results
}

/**
 * Tier 3: Check registry for driver service entries (installed but not running).
 * HKLM\SYSTEM\CurrentControlSet\Services stores all installed drivers.
 */
function scanByovdRegistry(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    for (const vd of VULNERABLE_DRIVERS) {
      for (const svcName of vd.serviceNames) {
        const regPath = `HKLM\\SYSTEM\\CurrentControlSet\\Services\\${svcName}`
        try {
          execSync(`reg query "${regPath}" /v ImagePath 2>nul`, {
            encoding: 'utf-8', timeout: 2000, windowsHide: true,
          })

          if (addFindingDedup(`byovd-reg:${svcName}`)) {
            results.push({
              path: `Hardware: BYOVD Registry`,
              fileName: `⚠ Vulnerable Driver Registered: ${svcName}`,
              type: 'hardware',
              risk: 'high',
              matches: [
                `Registry key: ${regPath}`,
                `Vulnerability: ${vd.description}`,
                `Abused by: ${vd.abusedBy.join(', ')}`,
                `⚠ Driver service is registered — may be loaded on demand`,
              ],
              size: 0,
              modifiedAt: new Date().toISOString(),
            })
          }
          break
        } catch {
          // reg query returns non-zero if key not found — expected
        }
      }
    }
  } catch { /* registry scan optional */ }

  return results
}

// ═══════════════════════════════════════════════════
// MAIN ENTRY POINT
// ═══════════════════════════════════════════════════

/**
 * Run full BYOVD scan — files + services + registry.
 * Returns ScanResult[] with findings.
 */
export function scanByovd(): ScanResult[] {
  const results: ScanResult[] = []

  // Tier 1: File existence + signature
  results.push(...scanByovdFiles())

  // Tier 2: Loaded/running services (most important — active threat)
  results.push(...scanByovdServices())

  // Tier 3: Registry remnants
  results.push(...scanByovdRegistry())

  return results
}
