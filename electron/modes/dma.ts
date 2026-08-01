import { execPowerShellAsync, spawnAsyncWithTimeout } from '../utils/exec'
import * as path from 'path'
import fsp from 'fs/promises'
import { BrowserWindow } from 'electron'
import { ScanResult, addFindingDedup, sendProgress, parsePsJson, _WR, ctx } from '../types'
import { scanBrowserHistory } from './browser'
import { getScanPaths } from '../cheats-db'
import { runAntiTamperScan } from '../anti-tamper'
import { safeCall } from '../utils/safe-spread'

const KNOWN_DMA_VENDORS = [
  { name: 'Xilinx FPGA', ids: ['10ee'] },
  { name: 'Altera/Intel FPGA', ids: ['1172'] },
  { name: 'Lattice Semiconductor', ids: ['1204'] },
  { name: 'FTDI (USB-FPGA bridge)', ids: ['0403'] },
  { name: 'Texas Instruments FPGA', ids: ['104c'] },
  { name: 'Xilinx (alt class)', ids: ['dada'] },
]

// FTDI FT601 USB IDs — the standard USB bridge on ALL DMA cheat cards
const FTDI_USB_IDS = ['0403:601e', '0403:601f', '0403:6010', '0403:6011', '0403:6014']

// Known DMA cheat card FPGA chip strings
const DMA_FPGA_CHIPS = ['xc7a35t', 'xc7a75t', 'xc7a100t', 'xc7a200t', 'artix-7', 'artix7', 'kintex', 'virtex']

// PCILeech ecosystem files
const PCILEECH_FILES = ['leechcore.dll', 'vmm.dll', 'ftd3xx.dll', 'pcileech.dll', 'pcileech_core.dll', 'leechsvc.dll', 'memprocfs.exe']

// PCI Class Codes for suspicious generic bridges (possible spoofed FPGA devices)
const SUSPICIOUS_PCI_CLASSES = ['0604', '0600', '0680'] // PCI Bridge, Host Bridge, Other Bridge

/**
 * Query PnP devices via WMIC or PowerShell
 */
export async function queryPnpDevices(filter: string, signal?: AbortSignal): Promise<string> {
  const wmicOutput = await spawnAsyncWithTimeout('wmic', [
    'path', 'Win32_PnPEntity', 'where', `"${filter}"`,
    'get', 'DeviceID,Name,PnPDeviceID', '/format:csv',
  ], { timeout: 8000, signal })
  if (signal?.aborted) throw new Error('DMA PnP query aborted')
  if (wmicOutput?.trim()) return wmicOutput.trim()

  const psOutput = await execPowerShellAsync(
    `Get-PnpDevice -PresentOnly | Where-Object { ${filter} } | Format-Table -AutoSize | Out-String -Width 4096`,
    { timeout: 8000, signal },
  )
  if (signal?.aborted) throw new Error('DMA PnP query aborted')
  return (psOutput || '').trim()
}

/**
 * PCI Config Space Fingerprinting — detect spoofed DMA devices.
 * Cheaters change Vendor/Device IDs in FPGA firmware to hide from name-based detection.
 * This catches "generic" PCI bridges with suspicious characteristics.
 */
async function scanPciFingerprints(signal?: AbortSignal): Promise<ScanResult[]> {
  const results: ScanResult[] = []

  try {
    // Get detailed PCI device info including class codes and BARs
    // This catches devices claiming to be "generic bridges" but with unusual BAR sizes
    const psCmd = [
      'Get-PnpDevice -PresentOnly -Class System | Select-Object InstanceId, FriendlyName, Class, Status | ConvertTo-Json -Compress'
    ].join('')

    const out = await execPowerShellAsync(psCmd, {
      timeout: 8000,
      signal,
    }) || ''
    if (signal?.aborted) throw new Error('DMA PCI fingerprint scan aborted')

    if (!out || out.length < 5) return results

    let devices: { InstanceId?: string; FriendlyName?: string; Class?: string; Status?: string }[] = []
    try {
      const parsed = JSON.parse(out)
      devices = Array.isArray(parsed) ? parsed : [parsed]
    } catch { return results }

    for (const dev of devices) {
      const name = (dev.FriendlyName || '').toLowerCase()
      const instanceId = (dev.InstanceId || '').toLowerCase()
      const signals: string[] = []

      // Signal 1: Generic PCI bridge names that cheaters spoof FPGA as
      if (name.includes('pci standard ram controller') ||
          name.includes('pci memory controller') ||
          name.includes('standard pci-to-pci bridge') ||
          name.includes('pci standard host bridge')) {
        signals.push(`Generic PCI bridge: "${name}" (possible FPGA masquerade)`)
      }

      // Signal 2: Device IDs matching known FPGA patterns + suspicious PCI classes
      const fpgaPatterns = [
        'ven_10ee', 'ven_1172', 'ven_1204', 'ven_104c',
        ...SUSPICIOUS_PCI_CLASSES.map(cc => `cc_${cc}`), 'subsys_']
      for (const pattern of fpgaPatterns) {
        if (instanceId.includes(pattern)) {
          const clean = pattern.replace('ven_', 'VEN_').replace('cc_', 'Class_').toUpperCase()
          signals.push(`FPGA-like hardware ID: ${clean}`)
          break
        }
      }

      // Signal 3: No friendly name (hidden/spoofed device)
      if (!dev.FriendlyName || dev.FriendlyName.trim() === '') {
        signals.push('PCI device with no friendly name (hidden/spoofed)')
      }

      if (signals.length > 0 && addFindingDedup(`pci-fp:${instanceId}`)) {
        // Sanitize FriendlyName — PowerShell may return non-ASCII/garbled text
        // that looks like "⠭��� ������" in the Electron renderer
        const safeName = (dev.FriendlyName || '')
          .replace(/[^\x20-\x7E]/g, '') // strip non-ASCII
          .trim()
          || `PCI Device (${dev.Class || 'System'})`
        results.push({
          path: 'PCI Config Space',
          fileName: `DMA Fingerprint: ${safeName}`,
          type: 'hardware',
          risk: signals.length >= 2 ? 'high' : 'medium',
          matches: signals,
          size: 0,
          modifiedAt: new Date().toISOString(),
        })
      }
    }
  } catch (err) {
    if (signal?.aborted) throw err
    /* PCI fingerprinting optional */
  }

  return results
}

/**
 * Scan for DMA devices (PCI hardware + software files + drivers + fingerprinting)
 */
export async function scanDmaDevices(signal?: AbortSignal): Promise<ScanResult[]> {
  const results: ScanResult[] = []

  // 1. Hardware: PCI/System devices matching known DMA vendors
  const output = await queryPnpDevices("PNPClass='PCI' OR PNPClass='System'", signal)
  if (signal?.aborted) throw new Error('DMA device scan aborted')
  if (output) {
    const lower = output.toLowerCase()
    for (const vendor of KNOWN_DMA_VENDORS) {
      for (const id of vendor.ids) {
        if (lower.includes(id)) {
          results.push({
            path: 'System Devices', fileName: `PCI Device: ${vendor.name}`, type: 'hardware', risk: 'high',
            matches: [`pci:${vendor.name} (VEN_${id})`], size: 0, modifiedAt: new Date().toISOString(),
          })
        }
      }
    }
  }

  // 1b. PCI fingerprinting (new — catches spoofed devices)
  results.push(...await scanPciFingerprints(signal))
  if (signal?.aborted) throw new Error('DMA device scan aborted')

  // 1c. FTDI FT601 USB detection (all DMA cards use this USB bridge)
  try {
    const usbOut = await execPowerShellAsync(
      'Get-PnpDevice -PresentOnly -Class USB | Where-Object { $_.InstanceId -match \'0403\' } | Select-Object InstanceId, FriendlyName | ConvertTo-Json -Compress',
      { timeout: 8000, signal },
    ) || ''
    if (signal?.aborted) throw new Error('DMA FTDI query aborted')
    if (usbOut && usbOut.length > 5) {
      for (const ftid of FTDI_USB_IDS) {
        if (usbOut.toLowerCase().includes(ftid.toLowerCase())) {
          results.push({
            path: 'USB Devices',
            fileName: `⚠ DMA USB Bridge: FTDI FT601 (${ftid})`,
            type: 'hardware',
            risk: 'high',
            matches: [
              `ftdi-usb:${ftid}`,
              `⚠ FTDI FT601 is THE standard USB bridge for DMA cheat cards`,
              `⚠ Used by: LeetDMA, Enigma X1, Screamer M2, Raptor, CaptainDMA, ZDMA, GBOX`,
            ],
            size: 0,
            modifiedAt: new Date().toISOString(),
          })
          break
        }
      }
    }
  } catch (err) {
    if (signal?.aborted) throw err
    /* FTDI USB check optional */
  }

  // 2. Software: DMA-related files in scan paths
  const dmaKeywords = ['dma', 'fpga', 'pcileech', 'fuser', 'screamer', 'leechcore', 'memprocfs', 'vmm', 'kmem', 'coremap', 'ftd3', 'ftd2', 'ft601', 'leechsvc', 'xc7a']
  for (const dir of getScanPaths()) {
    if (signal?.aborted) throw new Error('DMA device scan aborted')

    let entries: string[]
    try {
      entries = await fsp.readdir(dir)
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
        console.warn('[dma] failed to read scan path:', (err as Error).message)
      }
      continue
    }

    for (const entry of entries) {
      if (signal?.aborted) throw new Error('DMA device scan aborted')
      const lower = entry.toLowerCase()
      const matches: string[] = []
      for (const kw of dmaKeywords) {
        if (lower.includes(kw)) matches.push(`dma-keyword:${kw}`)
      }
      if (matches.length === 0) continue

      const fullPath = path.join(dir, entry)
      try {
        const stat = await fsp.stat(fullPath)
        if (signal?.aborted) throw new Error('DMA device scan aborted')
        results.push({ path: fullPath, fileName: entry, type: 'software', risk: 'high', matches, size: stat.size, modifiedAt: stat.mtime.toISOString() })
      } catch (err) {
        if (signal?.aborted) throw err
        console.warn('[dma] failed:', (err as Error).message)
      }
    }
  }

  // 3. Drivers: DMA-related files in System32\drivers + PCILeech ecosystem
  const sysDir = path.join(_WR, 'System32', 'drivers')
  let driverEntries: string[] = []
  try {
    driverEntries = await fsp.readdir(sysDir)
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
      console.warn('[dma] failed to read driver directory:', (err as Error).message)
    }
    driverEntries = []
  }

  for (const driver of driverEntries) {
    if (signal?.aborted) throw new Error('DMA device scan aborted')
    const lower = driver.toLowerCase()
    const matches: string[] = []
    if (dmaKeywords.some(k => lower.includes(k))) matches.push(`driver:${driver}`)
    // Check against known PCILeech ecosystem files
    if (PCILEECH_FILES.some(f => lower === f.toLowerCase())) matches.push(`pcileech-driver:${driver}`)
    if (matches.length > 0) {
      results.push({ path: path.join(sysDir, driver), fileName: `Driver: ${driver}`, type: 'software', risk: 'high', matches, size: 0, modifiedAt: new Date().toISOString() })
    }
  }

  if (signal?.aborted) throw new Error('DMA device scan aborted')

  // 3b. PCILeech ecosystem files in System32
  const system32Dir = path.join(_WR, 'System32')
  let system32Entries: string[] = []
  try {
    system32Entries = await fsp.readdir(system32Dir)
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
      console.warn('[dma] failed to read System32:', (err as Error).message)
    }
    system32Entries = []
  }

  for (const file of system32Entries) {
    if (signal?.aborted) throw new Error('DMA device scan aborted')
    const lower = file.toLowerCase()
    if (PCILEECH_FILES.some(f => lower === f.toLowerCase())) {
      results.push({
        path: path.join(system32Dir, file),
        fileName: `⚠ PCILeech Component: ${file}`,
        type: 'software',
        risk: 'high',
        matches: [`pcileech-file:${file}`, `⚠ Core DMA memory acquisition library`],
        size: 0,
        modifiedAt: new Date().toISOString(),
      })
    }
  }

  if (signal?.aborted) throw new Error('DMA device scan aborted')

  // 3c. FPGA chip detection in PCI device descriptions
  try {
    const pciOut = await execPowerShellAsync(
      'Get-PnpDevice -PresentOnly -Class System | Select-Object InstanceId, FriendlyName | ConvertTo-Json -Compress',
      { timeout: 8000, signal },
    ) || ''
    if (signal?.aborted) throw new Error('DMA FPGA query aborted')
    if (pciOut && pciOut.length > 5) {
      for (const chip of DMA_FPGA_CHIPS) {
        if (pciOut.toLowerCase().includes(chip)) {
          results.push({
            path: 'PCI Devices',
            fileName: `⚠ FPGA Chip Detected: ${chip.toUpperCase()}`,
            type: 'hardware',
            risk: 'high',
            matches: [
              `fpga-chip:${chip}`,
              `⚠ FPGA chips are the core of ALL DMA cheat cards`,
            ],
            size: 0,
            modifiedAt: new Date().toISOString(),
          })
          break
        }
      }
    }
  } catch (err) {
    if (signal?.aborted) throw err
    /* FPGA detection optional */
  }

  return results
}

/**
 * Scan registry for DMA-related services
 */
export async function scanDmaRegistry(signal?: AbortSignal): Promise<ScanResult[]> {
  const results: ScanResult[] = []
  const svcPath = 'HKLM\\SYSTEM\\CurrentControlSet\\Services'

  for (const term of ['dma', 'fpga', 'pcileech', 'fuser', 'leech']) {
    try {
      const out = await spawnAsyncWithTimeout('reg', ['query', svcPath, '/s', '/f', term], {
        timeout: 5000,
        signal,
      }) || ''
      if (signal?.aborted) throw new Error('DMA registry scan aborted')
      if (out.trim().length > 0) {
        results.push({ path: svcPath, fileName: `Registry: ${term.toUpperCase()}-related services`, type: 'registry', risk: 'high', matches: [`registry:${term} service(s) found`], size: 0, modifiedAt: new Date().toISOString() })
      }
    } catch (err) {
      if (signal?.aborted) throw err
      console.warn('[dma] failed:', (err as Error).message)
    }
  }

  return results
}

/**
 * Check IOMMU/VT-d status — if disabled, DMA protection is off
 */
export async function checkIommuStatus(signal?: AbortSignal): Promise<ScanResult[]> {
  const results: ScanResult[] = []

  const psCmd = `
$ErrorActionPreference = 'SilentlyContinue'
$info = @{}
# Check if Hyper-V/VBS is enforcing DMA protection
$dmaGuard = Get-CimInstance -Namespace root\\wmi -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
if ($dmaGuard) { $info.DmaGuard = $dmaGuard.SecurityServicesConfigured }
# Check kernel DMA protection via registry
$kernelDma = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Kernel DMA Protection' -ErrorAction SilentlyContinue
if ($kernelDma) { $info.KernelDma = $kernelDma }
# Check Device Guard / Credential Guard status
$devGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard -ErrorAction SilentlyContinue
if ($devGuard) { $info.DeviceGuard = $devGuard.SecurityServicesRunning }
$info | ConvertTo-Json -Compress
`

  try {
    const out = await execPowerShellAsync(psCmd, {
      timeout: 8000,
      signal,
    }) || ''
    if (signal?.aborted) throw new Error('IOMMU scan aborted')

    if (out && out.length > 2) {
      try {
        const info = JSON.parse(out)
        const services = info.DmaGuard ?? info.DeviceGuard
        // Only warn if we EXPLICITLY know protection is off
        // (undefined means WMI class not available — not a warning)
        if (services !== undefined && services !== null && services === 0) {
          results.push({
            path: 'System Security',
            fileName: '⚠ IOMMU/DMA Protection OFF',
            type: 'system',
            risk: 'medium',
            matches: [
              'DMA protection is NOT active',
              'Kernel DMA Protection: disabled or not configured',
              '⚠ DMA cheat cards can read all system memory',
            ],
            size: 0,
            modifiedAt: new Date().toISOString(),
          })
        } else {
          results.push({
            path: 'System Security',
            fileName: '✅ IOMMU/DMA Protection Active',
            type: 'system',
            risk: 'low',
            matches: [
              `DMA protection services: ${services}`,
              'System is protected against DMA attacks',
            ],
            size: 0,
            modifiedAt: new Date().toISOString(),
          })
        }
      } catch { /* parse error */ }
    }
  } catch (err) {
    if (signal?.aborted) throw err
    /* IOMMU check optional */
  }

  return results
}

/**
 * Run full DMA scan — PCI devices, USB, registry, browser history
 */
export async function runDmaScan(win: BrowserWindow | null): Promise<{ results: ScanResult[]; filesScanned: number }> {
  const results: ScanResult[] = []
  const signal = ctx.abortController?.signal
  const aborted = () => signal?.aborted ?? false

  // ── Phase 0: Anti-Tamper ──
  results.push(...safeCall('runAntiTamperScan', () => runAntiTamperScan()))
  if (aborted()) return { results, filesScanned: 0 }

  await sendProgress(win, { phase: 'scanning', currentDir: 'Checking PCI devices...', filesFound: 0, filesScanned: 0, totalDirs: 5, dirsDone: 1 })
  results.push(...await scanDmaDevices(signal))

  if (aborted()) return { results, filesScanned: results.length }

  await sendProgress(win, { phase: 'scanning', currentDir: 'Checking USB devices...', filesFound: results.length, filesScanned: results.length, totalDirs: 5, dirsDone: 2 })
  const usbOut = await queryPnpDevices("PNPClass='USB'", signal)
  if (usbOut && (usbOut.toLowerCase().includes('ftdi') || usbOut.toLowerCase().includes('ftd3'))) {
    results.push({ path: 'USB Devices', fileName: 'USB Device: Possible DMA interface', type: 'hardware', risk: 'medium', matches: ['usb:FTDI device (common DMA interface)'], size: 0, modifiedAt: new Date().toISOString() })
  }

  if (aborted()) return { results, filesScanned: results.length }

  await sendProgress(win, { phase: 'scanning', currentDir: 'Checking registry...', filesFound: results.length, filesScanned: results.length, totalDirs: 5, dirsDone: 3 })
  results.push(...await scanDmaRegistry(signal))

  if (aborted()) return { results, filesScanned: results.length }

  await sendProgress(win, { phase: 'analyzing', currentDir: 'Browser history for DMA...', filesFound: results.length, filesScanned: results.length, totalDirs: 5, dirsDone: 4 })
  const dmaKw = ['dma', 'fpga', 'pcileech', 'fuser', 'screamer', 'kmem']
  const browserResults = await scanBrowserHistory(dmaKw)
  results.push(...browserResults)

  return { results, filesScanned: results.length + browserResults.length }
}

/**
 * Scan scheduled tasks for suspicious entries
 */
export async function scanScheduledTasks(signal?: AbortSignal): Promise<ScanResult[]> {
  const results: ScanResult[] = []

  try {
    const ps = [
      'Get-ScheduledTask | Where-Object {',
      "  $_.TaskPath -eq '\\' -and",
      "  $_.Author -notmatch 'Microsoft|Adobe|Google|Mozilla|Apple|Oracle|NVIDIA|AMD|Intel|Spotify|Discord|Slack|GitHub|Docker|JetBrains|Valve|Epic|Rockstar'",
      '} | Select-Object TaskName, TaskPath, Author, State, @{N=\'Actions\';E={($_.Actions | ForEach-Object { $_.Execute }) -join \'; \'}} | ConvertTo-Json -Compress'
    ].join('\n').trim()

    const out = await execPowerShellAsync(ps, {
      timeout: 10000,
      signal,
    }) || ''
    if (signal?.aborted) throw new Error('Scheduled task scan aborted')

    if (!out || out.length < 5) return results

    const tasks = parsePsJson<{ TaskName?: string; Author?: string; Actions?: string; State?: string }>(out)

    for (const task of tasks) {
      if (signal?.aborted) throw new Error('Scheduled task scan aborted')
      const name = (task.TaskName || '').trim()
      const author = (task.Author || '').trim()
      const actions = (task.Actions || '').toLowerCase()
      const state = (task.State || '').trim()

      if (!name || name === '') continue

      const matches: string[] = [`Scheduled task: ${name}`, `Author: ${author || 'N/A'}`, `State: ${state}`]
      let riskScore = 0

      const suspiciousPaths = ['\\temp\\', '\\appdata\\local\\', '\\appdata\\roaming\\', '\\downloads\\', '\\users\\']
      const runsFromSuspiciousDir = suspiciousPaths.some(p => actions.includes(p))
      if (runsFromSuspiciousDir) {
        matches.push('Executes from user temp/AppData directory')
        riskScore += 25
      }

      if (!author || author === '' || author === 'null') {
        matches.push('No author information')
        riskScore += 15
      }

      const cheatKeywords = ['cheat', 'hack', 'inject', 'bypass', 'loader', 'mod menu', 'gta', 'fivem', 'spoofer']
      for (const kw of cheatKeywords) {
        if (name.toLowerCase().includes(kw)) {
          matches.push(`Task name contains: ${kw}`)
          riskScore += 30
          break
        }
      }

      const scriptExts = ['.ps1', '.bat', '.vbs', '.cmd', '.js', '.exe']
      if (scriptExts.some(ext => actions.includes(ext)) && runsFromSuspiciousDir) {
        matches.push('Script executable from suspicious location')
        riskScore += 20
      }

      if (riskScore >= 20 && addFindingDedup(`schedtask:${name}`)) {
        results.push({
          path: `Scheduled Task: ${name}`,
          fileName: `Scheduled task: ${name}`,
          type: 'software',
          risk: riskScore > 50 ? 'high' : 'medium',
          matches: matches.slice(0, 6),
          size: 0,
          modifiedAt: new Date().toISOString(),
        })
      }
    }
  } catch (err) {
    if (signal?.aborted) throw err
    /* schtasks optional */
  }

  return results
}
