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

import { execPowerShell, execWithTimeout } from '../utils/exec'
import * as fs from 'fs'
import * as path from 'path'
import { fileURLToPath } from 'url'
import { _WR, type ScanResult, addFindingDedup } from '../types'
import { checkDigitalSignature, batchCheckSignatures } from '../heuristic'

// __dirname equivalent for ESM
const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

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
  // ── NEW 2025-2026: Drivers weaponized by cheat devs (research: Bellator Cyber, Connect Securonix) ──
  {
    fileNames: ['GameDriverX64.sys', 'GameDriver.sys'],
    serviceNames: ['GameDriverX64', 'GameDriver'],
    description: 'CVE-2025-61155 — GameDriverX64 anti-cheat driver abused to kill EDR/anti-cheat processes via IOCTL 0x222040',
    abusedBy: ['Interlock ransomware', 'Hotta Killer', 'cheat EDR-killers'],
  },
  {
    fileNames: ['iqvw64e.sys'],
    serviceNames: ['iqvw64e'],
    description: 'Intel Network Adapter Diagnostic Driver — vulnerable IOCTL allows kernel R/W',
    abusedBy: ['KDMapper variants', 'BYOVD exploit chains'],
  },
  {
    fileNames: ['nvoclock.sys'],
    serviceNames: ['nvoclock', 'NVOCLOCK'],
    description: 'NVIDIA overclocking driver — vulnerable IOCTL allows MSR write / kernel execution',
    abusedBy: ['Cheat kernel loaders', 'manual mappers'],
  },
  {
    fileNames: ['AswArPot.sys'],
    serviceNames: ['aswArPot'],
    description: 'Avast Anti-Rootkit driver — insufficient access control allows kernel R/W',
    abusedBy: ['EDR killers (Lazarus group)', 'Process termination tools'],
  },
  {
    fileNames: ['zamguard64.sys', 'zamguard32.sys'],
    serviceNames: ['ZAM_Guard', 'zamguard64'],
    description: 'Zemana Anti-Malware driver — vulnerable IOCTL allows kernel memory manipulation',
    abusedBy: ['BYOVD toolkits', 'kernel privilege escalation'],
  },
  {
    fileNames: ['viragt64.sys'],
    serviceNames: ['viragt64'],
    description: 'ViRobot anti-virus driver — IOCTL handler allows arbitrary process termination from user mode',
    abusedBy: ['Anti-cheat killer utilities', 'Terminator tools'],
  },
  {
    fileNames: ['atillk64.sys'],
    serviceNames: ['atillk64'],
    description: 'AMD ATI driver — vulnerable IOCTL grants physical memory R/W',
    abusedBy: ['Kernel exploit chains', 'BYOVD mappers'],
  },
  // ── LOLDrivers Top-13: most exploited vulnerable drivers (2025-2026) ──
  // Source: loldrivers.io / Microsoft Vulnerable Driver Blocklist
  {
    fileNames: ['AsrOmg.sys'],
    serviceNames: ['AsrOmg'],
    description: 'ASUS Operation Manual driver — physical memory R/W via vulnerable IOCTL',
    abusedBy: ['Kernel exploit kits', 'manual mappers', 'process hollowing tools'],
  },
  {
    fileNames: ['ene.sys'],
    serviceNames: ['ene'],
    description: 'ENE RGB controller driver — vulnerable IOCTL allows MSR write / kernel memory R/W',
    abusedBy: ['Cheat kernel loaders', 'HWID spoofers', 'KDMapper forks'],
  },
  {
    fileNames: ['GLCKIO2.sys'],
    serviceNames: ['GLCKIO2'],
    description: 'ASUS GPU Tweak II driver — vulnerable IOCTL grants kernel R/W',
    abusedBy: ['GPU overclock exploit chains', 'manual mappers'],
  },
  {
    fileNames: ['MsIo64.sys'],
    serviceNames: ['MsIo64'],
    description: 'MSI motherboard driver — vulnerable IOCTL allows I/O port and MSR access',
    abusedBy: ['HWID spoofer tools', 'MSR-based cheat loaders'],
  },
  {
    fileNames: ['NalDrv.sys'],
    serviceNames: ['NalDrv'],
    description: 'Nero AG driver — physical memory R/W via insufficient access control',
    abusedBy: ['Kernel exploit frameworks', 'cheat driver loaders'],
  },
  {
    fileNames: ['RadHwMgr.sys'],
    serviceNames: ['RadHwMgr'],
    description: 'AMD hardware manager driver — vulnerable IOCTL grants physical memory access',
    abusedBy: ['AMD system exploit chains', 'HWID manipulation tools'],
  },
  {
    fileNames: ['Rzpnk.sys'],
    serviceNames: ['Rzpnk'],
    description: 'Razer peripheral driver — vulnerable IOCTL allows kernel memory manipulation',
    abusedBy: ['Gaming peripheral exploit kits', 'BYOVD toolchains'],
  },
  {
    fileNames: ['Semav6msr64.sys'],
    serviceNames: ['Semav6msr64'],
    description: 'SEMA driver — vulnerable MSR write access allows kernel code execution',
    abusedBy: ['MSR-based loader tools', 'kernel privilege escalation'],
  },
  {
    fileNames: ['EneTechIo.sys'],
    serviceNames: ['EneTechIo'],
    description: 'ENE Technology I/O driver — vulnerable IOCTL grants arbitrary I/O port access',
    abusedBy: ['HW communication tools', 'DMA card initialization'],
  },
  {
    fileNames: ['WinRing0x64.sys'],
    serviceNames: ['WinRing0x64'],
    description: 'OpenLibSys WinRing0 — vulnerable I/O port and MSR access from user mode',
    abusedBy: ['Fan control abuse', 'kernel R/W bridges', 'HWID spoof chains'],
  },
  {
    fileNames: ['AsUpIO.sys'],
    serviceNames: ['AsUpIO'],
    description: 'ASUS Update I/O driver — vulnerable I/O port access allows kernel communication',
    abusedBy: ['Firmware manipulation tools', 'BYOVD bridge drivers'],
  },
  {
    fileNames: ['inpoutx64.sys', 'inpout32.sys'],
    serviceNames: ['inpoutx64', 'inpout32'],
    description: 'HighResolutionEnt inpout driver — I/O port access from user mode',
    abusedBy: ['Hardware control abuse', 'DMA card helpers'],
  },
  {
    fileNames: ['HwOs2Ec.sys'],
    serviceNames: ['HwOs2Ec'],
    description: 'ASUS hardware monitor driver — vulnerable IOCTL allows kernel memory access',
    abusedBy: ['System monitoring abuse', 'kernel information leaks'],
  },
]

// Additional drive-by detection: filenames commonly associated with BYOVD
const BYOVD_FILENAME_PATTERNS = [
  'kprocesshacker', 'winio', 'phymem', 'dbk', 'cpuz',
  'gdrv', 'rtcore', 'capcom', 'dump64',
  'asromg', 'ene', 'glckio', 'msio', 'naldrv',
  'radhw', 'rzpnk', 'semav6', 'enetech',
  'winring0', 'asupio', 'inpout', 'hwos2ec',
]

// ═══════════════════════════════════════════════════
// JSON-BASED DRIVER LOADING (LOLDrivers)
// ═══════════════════════════════════════════════════
// Loads additional drivers from loldrivers.json at runtime.
// This allows updating signatures WITHOUT recompiling the app.
// The hardcoded list (VULNERABLE_DRIVERS) acts as a reliable fallback.

let _mergedDrivers: VulnerableDriver[] | null = null
let _mergedPatterns: string[] | null = null

function loadLolDrivers(): { drivers: VulnerableDriver[]; patterns: string[] } {
  if (_mergedDrivers && _mergedPatterns) {
    return { drivers: _mergedDrivers, patterns: _mergedPatterns }
  }

  const merged = [...VULNERABLE_DRIVERS]
  const patterns = [...BYOVD_FILENAME_PATTERNS]

  // Build dedup set from hardcoded service names
  const hardcodedServiceNames = new Set(
    VULNERABLE_DRIVERS.flatMap(d => d.serviceNames).map(s => s.toLowerCase())
  )

  try {
    const jsonPath = path.join(__dirname, '..', 'loldrivers.json')
    if (fs.existsSync(jsonPath)) {
      const raw = fs.readFileSync(jsonPath, 'utf-8')
      const jsonDrivers: VulnerableDriver[] = JSON.parse(raw)

      let newCount = 0
      for (const jd of jsonDrivers) {
        // Skip duplicates by service name
        const isDuplicate = jd.serviceNames.some(sn =>
          hardcodedServiceNames.has(sn.toLowerCase())
        )
        if (isDuplicate) continue

        merged.push(jd)
        newCount++

        // Extract filename bases for pattern-based broad scan
        for (const fn of jd.fileNames) {
          const base = fn.toLowerCase().replace(/\.(sys|dll|exe)$/i, '')
          if (!patterns.includes(base) && base.length >= 3) {
            patterns.push(base)
          }
        }
      }

      if (newCount > 0) {
        console.log(
          `[BYOVD] Loaded ${newCount} additional drivers from loldrivers.json (total: ${merged.length})`
        )
      }
    }
  } catch {
    // JSON load failed — silently fall back to hardcoded list
  }

  _mergedDrivers = merged
  _mergedPatterns = patterns
  return { drivers: merged, patterns }
}

/** Get all drivers (hardcoded + JSON). Result is cached after first call. */
function getDrivers(): VulnerableDriver[] {
  return loadLolDrivers().drivers
}

/** Get all filename patterns (hardcoded + JSON). Result is cached after first call. */
function getPatterns(): string[] {
  return loadLolDrivers().patterns
}

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

    for (const vd of getDrivers()) {
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
    // NOTE: skip files already matched by exact name in the first loop above
    const alreadyMatched = new Set(
      results.map(r => r.fileName?.toLowerCase() || '')
    )
    // ── BATCH: Pre-warm signature cache for all candidate files ──
    const patterns = getPatterns()
    const candidatePaths: string[] = []
    for (const file of fs.readdirSync(driversDir)) {
      const lower = file.toLowerCase()
      if (alreadyMatched.has(lower)) continue
      if (patterns.some(p => lower.includes(p))) {
        candidatePaths.push(path.join(driversDir, file))
      }
    }
    if (candidatePaths.length > 0) {
      batchCheckSignatures(candidatePaths)
    }

    for (const filePath of candidatePaths) {
      const file = path.basename(filePath)
      const lower = file.toLowerCase()

      // Only flag if file is NOT digitally signed (uses shared cache — 0 PowerShell calls)
      try {
        const isSigned = checkDigitalSignature(filePath)

        if (!isSigned && addFindingDedup(`byovd-pattern:${file}`)) {
          results.push({
            path: `Hardware: BYOVD Driver File`,
            fileName: `⚠ Suspicious Driver: ${file} (unsigned)`,
            type: 'hardware',
            risk: 'medium',
            matches: [
              `Found: C:\\Windows\\System32\\drivers\\${file}`,
              `Matches BYOVD filename pattern: "${patterns.find(p => lower.includes(p)) || 'unknown'}"`,
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
    const out = execPowerShell(psScript, { timeout: 8000 }) || ''

    if (!out || out === '[]' || out.length < 5) return results

    let driverList: { Name?: string; DisplayName?: string; PathName?: string; State?: string }[] = []
    try {
      driverList = JSON.parse(out)
      if (!Array.isArray(driverList)) driverList = [driverList]
    } catch { return results }

    const loadedNames = new Set(driverList.map(d => (d.Name || '').toLowerCase()))
    const loadedPaths = new Set(driverList.map(d => (d.PathName || '').toLowerCase()))

    for (const vd of getDrivers()) {
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
    for (const vd of getDrivers()) {
      for (const svcName of vd.serviceNames) {
        const regPath = `HKLM\\SYSTEM\\CurrentControlSet\\Services\\${svcName}`
        try {
          execWithTimeout(`reg query "${regPath}" /v ImagePath 2>nul`, {
            timeout: 2000,
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
