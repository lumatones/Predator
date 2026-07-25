import { execSync } from 'child_process'
import * as path from 'path'
import * as fs from 'fs'
import { BrowserWindow } from 'electron'
import { ScanResult, addFindingDedup, sendProgress, execCmd, _WR } from '../types'
import { scanBrowserHistory } from './browser'
import { getScanPaths } from '../cheats-db'

const KNOWN_DMA_VENDORS = [
  { name: 'Xilinx', ids: ['10ee'] },
  { name: 'Altera/Intel FPGA', ids: ['1172'] },
  { name: 'Lattice Semiconductor', ids: ['1204'] },
  { name: 'FTDI (USB-FPGA bridge)', ids: ['0403'] },
  { name: 'Texas Instruments (FPGA)', ids: ['104c'] },
]

/**
 * Query PnP devices via WMIC or PowerShell
 */
export function queryPnpDevices(filter: string): string {
  return execCmd(
    `wmic path Win32_PnPEntity where "${filter}" get DeviceID,Name,PnPDeviceID /format:csv 2>nul`,
    `Get-PnpDevice -PresentOnly | Where-Object { ${filter} } | Format-Table -AutoSize | Out-String -Width 4096`,
  ).trim()
}

/**
 * Scan for DMA devices (PCI hardware + software files + drivers)
 */
export function scanDmaDevices(): ScanResult[] {
  const results: ScanResult[] = []

  // 1. Hardware: PCI/System devices matching known DMA vendors
  const output = queryPnpDevices("PNPClass='PCI' OR PNPClass='System'")
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

  // 2. Software: DMA-related files in scan paths
  const dmaKeywords = ['dma', 'fpga', 'pcileech', 'fuser', 'screamer', 'leechcore', 'memprocfs', 'vmm', 'kmem', 'coremap', 'ftd3', 'ftd2']
  for (const dir of getScanPaths()) {
    if (!fs.existsSync(dir)) continue
    try {
      for (const entry of fs.readdirSync(dir)) {
        const lower = entry.toLowerCase()
        const matches: string[] = []
        for (const kw of dmaKeywords) {
          if (lower.includes(kw)) matches.push(`dma-keyword:${kw}`)
        }
        if (matches.length > 0) {
          try {
            const stat = fs.statSync(path.join(dir, entry))
            results.push({ path: path.join(dir, entry), fileName: entry, type: 'software', risk: 'high', matches, size: stat.size, modifiedAt: stat.mtime.toISOString() })
          } catch (_e) { /* skip */ }
        }
      }
    } catch (_e) { /* skip */ }
  }

  // 3. Drivers: DMA-related files in System32\drivers
  try {
    const sysDir = path.join(_WR, 'System32', 'drivers')
    if (fs.existsSync(sysDir)) {
      for (const driver of fs.readdirSync(sysDir)) {
        const lower = driver.toLowerCase()
        const matches: string[] = []
        if (dmaKeywords.some(k => lower.includes(k))) matches.push(`driver:${driver}`)
        if (matches.length > 0) {
          results.push({ path: path.join(sysDir, driver), fileName: `Driver: ${driver}`, type: 'software', risk: 'high', matches, size: 0, modifiedAt: new Date().toISOString() })
        }
      }
    }
  } catch (_e) { /* skip */ }

  return results
}

/**
 * Scan registry for DMA-related services
 */
export function scanDmaRegistry(): ScanResult[] {
  const results: ScanResult[] = []
  const svcPath = 'HKLM\\SYSTEM\\CurrentControlSet\\Services'

  for (const term of ['dma', 'fpga', 'pcileech', 'fuser', 'leech']) {
    try {
      const out = execSync(`reg query "${svcPath}" /s /f "${term}" 2>nul`, { encoding: 'utf-8' as const, timeout: 5000 })
      if (out.trim().length > 0) {
        results.push({ path: svcPath, fileName: `Registry: ${term.toUpperCase()}-related services`, type: 'registry', risk: 'high', matches: [`registry:${term} service(s) found`], size: 0, modifiedAt: new Date().toISOString() })
      }
    } catch (_e) { /* skip */ }
  }

  return results
}

/**
 * Run full DMA scan — PCI devices, USB, registry, browser history
 */
export async function runDmaScan(win: BrowserWindow | null): Promise<{ results: ScanResult[]; filesScanned: number }> {
  const results: ScanResult[] = []

  await sendProgress(win, { phase: 'scanning', currentDir: 'Checking PCI devices...', filesFound: 0, filesScanned: 0, totalDirs: 5, dirsDone: 1 })
  results.push(...scanDmaDevices())

  await sendProgress(win, { phase: 'scanning', currentDir: 'Checking USB devices...', filesFound: results.length, filesScanned: results.length, totalDirs: 5, dirsDone: 2 })
  const usbOut = queryPnpDevices("PNPClass='USB'")
  if (usbOut && (usbOut.toLowerCase().includes('ftdi') || usbOut.toLowerCase().includes('ftd3'))) {
    results.push({ path: 'USB Devices', fileName: 'USB Device: Possible DMA interface', type: 'hardware', risk: 'medium', matches: ['usb:FTDI device (common DMA interface)'], size: 0, modifiedAt: new Date().toISOString() })
  }

  await sendProgress(win, { phase: 'scanning', currentDir: 'Checking registry...', filesFound: results.length, filesScanned: results.length, totalDirs: 5, dirsDone: 3 })
  results.push(...scanDmaRegistry())

  await sendProgress(win, { phase: 'analyzing', currentDir: 'Browser history for DMA...', filesFound: results.length, filesScanned: results.length, totalDirs: 5, dirsDone: 4 })
  const dmaKw = ['dma', 'fpga', 'pcileech', 'fuser', 'screamer', 'kmem']
  const browserResults = await scanBrowserHistory(dmaKw)
  results.push(...browserResults)

  return { results, filesScanned: results.length + browserResults.length }
}

/**
 * Scan scheduled tasks for suspicious entries
 */
export function scanScheduledTasks(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    const ps = `
Get-ScheduledTask | Where-Object {
  $_.TaskPath -eq '\\' -and
  $_.Author -notmatch 'Microsoft|Adobe|Google|Mozilla|Apple|Oracle|NVIDIA|AMD|Intel|Spotify|Discord|Slack|GitHub|Docker|JetBrains|Valve|Epic|Rockstar'
} | Select-Object TaskName, TaskPath, Author, State, @{N='Actions';E={($_.Actions | ForEach-Object { $_.Execute }) -join '; '}} | ConvertTo-Json -Compress
`.trim()

    const out = execSync(`powershell -Command "${ps.replace(/"/g, '\\"').replace(/\n/g, '; ')}"`, {
      encoding: 'utf-8' as const,
      timeout: 10000,
      windowsHide: true,
    }).trim()

    if (!out || out.length < 5) return results

    const parsed = JSON.parse(out)
    const tasks = Array.isArray(parsed) ? parsed : [parsed]

    for (const task of tasks) {
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
  } catch { /* schtasks optional */ }

  return results
}
