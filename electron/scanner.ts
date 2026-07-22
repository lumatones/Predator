import { ipcMain, BrowserWindow } from 'electron'
import fs from 'fs'
import path from 'path'
import os from 'os'
import { execSync } from 'child_process'

import {
  KNOWN_PROCESSES,
  KNOWN_CHEAT_FILES,
  KNOWN_LUA_SCRIPTS,
  KNOWN_CHEAT_FOLDERS,
  KNOWN_BINARY_SIGNATURES,
  REGISTRY_SCAN_KEYS,
  getScanPaths,
  TARGET_EXTENSIONS,
} from './cheats-db'

// ── Types ──────────────────────────────────────

export type ScanMode = 'files' | 'processes' | 'cheats' | 'dma'

export interface ScanResult {
  path: string
  fileName: string
  type: 'file' | 'browser' | 'process' | 'registry' | 'hardware' | 'software'
  risk: 'high' | 'medium' | 'low'
  matches: string[]
  size: number
  modifiedAt: string
}

export interface ScanProgress {
  phase: 'scanning' | 'analyzing' | 'done'
  currentDir: string
  filesFound: number
  filesScanned: number
  totalDirs: number
  dirsDone: number
}

export interface ScanResponse {
  results: ScanResult[]
  summary: {
    totalScanned: number
    suspiciousFiles: number
    highRiskCount: number
    scanTimeMs: number
  }
}

// ── Config ──────────────────────────────────────

const _PF = process.env.ProgramFiles || 'C:\\Program Files'
const _PF86 = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)'
const _PD = process.env.ProgramData || 'C:\\ProgramData'
const _WR = process.env.SystemRoot || 'C:\\Windows'

// All known cheat/process names as keywords for matching
const ALL_CHEAT_KEYWORDS = [
  ...KNOWN_PROCESSES.map(n => n.replace(/\.exe$/i, '').replace(/_\*\.exe$/i, '').replace(/\*\.exe$/i, '')),
  ...KNOWN_CHEAT_FILES.map(n => n.replace(/\.(dll|exe|asi)$/i, '')),
  ...KNOWN_LUA_SCRIPTS.map(n => n.replace(/\.lua$/i, '')),
  ...KNOWN_CHEAT_FOLDERS,
  'cheat', 'hack', 'inject', 'bypass', 'mod menu', 'trainer',
  'aimbot', 'wallhack', 'esp', 'triggerbot', 'norecoil', 'nospread',
  'godmode', 'teleport', 'moneydrop', 'recovery', 'unlockall',
  'nightfall', 'dma', 'fpga', 'pcileech', 'fuser', 'screamer',
  'kmem', 'memprocfs', 'winpmem',
]

const SUSPICIOUS_PATTERNS = [
  /[Nn]ightfall/i,
  /[Cc]heats?\s*(?:folder|dir|menu)/i,
  /[Mm]od\s*[Mm]enu/i,
  /[Ii]nject/i,
  /[Bb]ypass/i,
  /[Hh]ook\d*\.dll/i,
  /[Ss]cript\s*[Hh]ook/i,
  /[Aa]imbot/i,
  /[Ww]allhack/i,
  /[Dd][Mm][Aa]/i,
  /[Ff][Pp][Gg][Aa]/i,
  /[Pp][Cc][Ii]\s*[Ll]eech/i,
]

const BROWSER_DIRS = [
  path.join(os.homedir(), 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'History'),
  path.join(os.homedir(), 'AppData', 'Local', 'Yandex', 'YandexBrowser', 'User Data', 'Default', 'History'),
  path.join(os.homedir(), 'AppData', 'Roaming', 'Opera Software', 'Opera Stable', 'History'),
]

// ── Helpers ────────────────────────────────────

function getFileRiskLevel(fileName: string, matches: string[]): 'high' | 'medium' | 'low' {
  const ext = path.extname(fileName).toLowerCase()
  const highRiskExts = ['.exe', '.dll', '.sys', '.drv', '.bat', '.ps1', '.vbs', '.ahk']
  const mediumRiskExts = ['.js', '.lua', '.py', '.cs', '.asi', '.luac']

  const hasHighKeyword = matches.some(k =>
    ['dll inject', 'memory hack', 'injector', 'aimbot', 'wallhack',
     'triggerbot', 'dma', 'fpga', 'pcileech', 'fuser'].includes(k)
  )

  if ((highRiskExts.includes(ext) && hasHighKeyword) || matches.length >= 3) return 'high'
  if (highRiskExts.includes(ext) || mediumRiskExts.includes(ext) || matches.length >= 2) return 'medium'
  return 'low'
}

function* walkDir(dirPath: string): Generator<string> {
  try {
    const entries = fs.readdirSync(dirPath, { withFileTypes: true })
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name)
      if (entry.isDirectory()) {
        if (!entry.name.startsWith('.') && entry.name !== 'node_modules' && entry.name !== 'Temp') {
          yield* walkDir(fullPath)
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase()
        if (TARGET_EXTENSIONS.has(ext)) yield fullPath
      }
    }
  } catch { /* skip */ }
}

// Yields to the event loop so the renderer can receive progress events.
// Without this, all synchronous work (readdirSync, statSync, execSync)
// queues up and the renderer only sees the final 'done' event.
async function sendProgress(win: BrowserWindow | null, data: ScanProgress) {
  win?.webContents.send('scan-progress', data)
  // Yield control back to the event loop so the IPC message actually gets delivered
  await new Promise(resolve => setImmediate(resolve))
}

function execCmd(cmd: string, psCmd: string, opts = {}): string {
  try {
    return execSync(cmd, { encoding: 'utf-8', timeout: 8000, ...opts })
  } catch {
    try {
      return execSync(psCmd, { encoding: 'utf-8', timeout: 8000, ...opts })
    } catch {
      return ''
    }
  }
}

// ── Pre-normalized arrays for fast substring matching ──

const _PROC_BASES = KNOWN_PROCESSES.map(n =>
  n.toLowerCase()
    .replace(/\.exe$/i, '')
    .replace(/\*\.exe$/i, '')
)
const _FILE_NAMES = KNOWN_CHEAT_FILES.map(n => n.toLowerCase())
const _LUA_NAMES = KNOWN_LUA_SCRIPTS.map(n => n.toLowerCase())
const _FOLDER_NAMES = KNOWN_CHEAT_FOLDERS.map(n => n.toLowerCase())

// ── Check if a name matches any KNOWN process/file/folder ──

const _cheatNameCache = new Map<string, string[]>()

function matchKnownCheat(name: string): string[] {
  const lower = name.toLowerCase()

  // Cache hit → return immediately
  const cached = _cheatNameCache.get(lower)
  if (cached !== undefined) return cached

  const matches: string[] = []

  // Substring matching (preserves original .includes() behavior)
  for (const base of _PROC_BASES) {
    if (lower.includes(base)) matches.push(`process:${base}`)
  }
  for (const file of _FILE_NAMES) {
    if (lower.includes(file)) matches.push(`file:${file}`)
  }
  for (const lua of _LUA_NAMES) {
    if (lower.includes(lua)) matches.push(`lua:${lua}`)
  }
  for (const folder of _FOLDER_NAMES) {
    if (lower.includes(folder)) matches.push(`folder:${folder}`)
  }

  _cheatNameCache.set(lower, matches)
  return matches
}

// ═══════════════════════════════════════════════
// MODE 1: FILE SCAN
// ═══════════════════════════════════════════════

async function scanFile(filePath: string): Promise<ScanResult | null> {
  try {
    const stat = fs.statSync(filePath)
    if (!stat.isFile() || stat.size > 5 * 1024 * 1024) return null

    const fileName = path.basename(filePath)
    const matches: string[] = []

    // Match against ALL cheat signatures
    const sigMatches = matchKnownCheat(fileName)
    matches.push(...sigMatches)

    // Regex patterns
    for (const pattern of SUSPICIOUS_PATTERNS) {
      if (pattern.test(fileName)) matches.push(`pattern:${pattern.source.replace(/\\/g, '')}`)
    }

    // Text content scanning
    const ext = path.extname(filePath).toLowerCase()
    const textExts = new Set(['.txt', '.log', '.json', '.xml', '.cfg', '.ini', '.js', '.lua', '.py', '.cs', '.bat', '.ps1', '.vbs', '.ahk', '.luac'])
    if (textExts.has(ext) && stat.size < 512 * 1024) {
      try {
        const content = fs.readFileSync(filePath, 'utf-8').toLowerCase()
        for (const keyword of ALL_CHEAT_KEYWORDS) {
          if (content.includes(keyword)) matches.push(`content:${keyword}`)
        }
      } catch { /* binary */ }
    }

    // Binary signature scanning (.exe, .dll, .sys, .asi)
    const binaryExts = new Set(['.exe', '.dll', '.sys', '.drv', '.asi', '.luac'])
    if (binaryExts.has(ext) && stat.size >= 1024 && stat.size < 50 * 1024 * 1024) {
      try {
        const buffer = fs.readFileSync(filePath)
        for (const sig of KNOWN_BINARY_SIGNATURES) {
          if (buffer.includes(sig)) matches.push(`binary-sig:${sig.toString('utf-8').slice(0, 30)}`)
        }
      } catch { /* skip */ }
    }

    if (matches.length === 0) return null
    return {
      path: filePath, fileName: path.basename(filePath), type: 'file',
      risk: getFileRiskLevel(path.basename(filePath), matches),
      matches, size: stat.size, modifiedAt: stat.mtime.toISOString(),
    }
  } catch { return null }
}

async function scanBrowserHistory(keywords?: string[]): Promise<ScanResult[]> {
  const kw = keywords || ALL_CHEAT_KEYWORDS
  const results: ScanResult[] = []

  for (const historyPath of BROWSER_DIRS) {
    try {
      if (!fs.existsSync(historyPath)) continue
      const stat = fs.statSync(historyPath)
      if (stat.size > 10 * 1024 * 1024) continue

      const content = fs.readFileSync(historyPath, 'utf-8').toLowerCase()
      const found: string[] = []

      for (const keyword of kw) {
        if (content.includes(keyword.toLowerCase())) found.push(`browser:${keyword}`)
      }

      if (found.length > 0) {
        const browserName = path.basename(path.dirname(path.dirname(path.dirname(historyPath))))
        results.push({
          path: historyPath, fileName: `History (${browserName})`, type: 'browser',
          risk: found.length >= 3 ? 'high' : found.length >= 2 ? 'medium' : 'low',
          matches: found, size: stat.size, modifiedAt: stat.mtime.toISOString(),
        })
      }
    } catch { /* skip */ }
  }

  return results
}

async function runFileScan(win: BrowserWindow | null): Promise<{ results: ScanResult[]; filesScanned: number }> {
  const results: ScanResult[] = []
  let filesScanned = 0
  const scanDirs = getScanPaths()

  for (let i = 0; i < scanDirs.length; i++) {
    const dir = scanDirs[i]
    if (!fs.existsSync(dir)) {
      // Still count non-existing dirs as 'done' so progress shows something
      await sendProgress(win, { phase: 'scanning', currentDir: `${dir} (skipped)`, filesFound: results.length, filesScanned, totalDirs: scanDirs.length, dirsDone: i + 1 })
      continue
    }

    await sendProgress(win, { phase: 'scanning', currentDir: dir, filesFound: results.length, filesScanned, totalDirs: scanDirs.length, dirsDone: i + 1 })

    const files: string[] = []
    for (const filePath of walkDir(dir)) files.push(filePath)

    for (const filePath of files) {
      filesScanned++
      const r = await scanFile(filePath)
      if (r) results.push(r)
      if (filesScanned % 15 === 0) {
        await sendProgress(win, { phase: 'scanning', currentDir: dir, filesFound: results.length, filesScanned, totalDirs: scanDirs.length, dirsDone: i + 1 })
      }
    }

    // Update after finishing this directory
    await sendProgress(win, { phase: 'scanning', currentDir: dir, filesFound: results.length, filesScanned, totalDirs: scanDirs.length, dirsDone: i + 1 })
  }

  return { results, filesScanned }
}

// ═══════════════════════════════════════════════
// MODE 2: PROCESS SCAN (expanded)
// ═══════════════════════════════════════════════

function scanRunningProcesses(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    const output = execSync('tasklist /FO CSV /NH', { encoding: 'utf-8', timeout: 5000 })
    for (const line of output.trim().split('\n')) {
      try {
        const parts = line.match(/"([^"]+)","(\d+)","(\d+)","([^"]+)"/)
        if (!parts) continue
        const name = parts[1].toLowerCase()
        const pid = parseInt(parts[2], 10)
        const memStr = parts[3].replace(/[^\d]/g, '')
        const memory = parseInt(memStr, 10) || 0

        const matches = matchKnownCheat(name)

        if (matches.length > 0) {
          results.push({
            path: `process:${parts[1]} (PID: ${pid})`, fileName: parts[1], type: 'process',
            risk: matches.length >= 2 ? 'high' : 'medium',
            matches, size: memory * 1024, modifiedAt: new Date().toISOString(),
          })
        }
      } catch { /* skip */ }
    }
  } catch { /* tasklist failed */ }

  return results
}

function scanRecentItems(): ScanResult[] {
  const results: ScanResult[] = []
  const recentDir = path.join(os.homedir(), 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Recent')

  try {
    if (!fs.existsSync(recentDir)) return results
    for (const item of fs.readdirSync(recentDir)) {
      const matches = matchKnownCheat(item)
      if (matches.length > 0) {
        const itemPath = path.join(recentDir, item)
        try {
          const stat = fs.statSync(itemPath)
          results.push({ path: itemPath, fileName: item, type: 'file', risk: matches.length >= 2 ? 'high' : 'medium', matches, size: stat.size, modifiedAt: stat.mtime.toISOString() })
        } catch { /* skip */ }
      }
    }
  } catch { /* skip */ }

  return results
}

function scanPrefetchFiles(): ScanResult[] {
  const results: ScanResult[] = []
  const prefetchDir = path.join(_WR, 'Prefetch')

  try {
    if (!fs.existsSync(prefetchDir)) return results
    for (const file of fs.readdirSync(prefetchDir)) {
      const matches = matchKnownCheat(file)
      if (matches.length > 0) {
        const filePath = path.join(prefetchDir, file)
        try {
          const stat = fs.statSync(filePath)
          results.push({ path: filePath, fileName: file, type: 'file', risk: matches.length >= 2 ? 'high' : 'medium', matches, size: stat.size, modifiedAt: stat.mtime.toISOString() })
        } catch { /* skip */ }
      }
    }
  } catch { /* skip */ }

  return results
}

async function runProcessScan(win: BrowserWindow | null): Promise<{ results: ScanResult[]; filesScanned: number }> {
  const results: ScanResult[] = []

  await sendProgress(win, { phase: 'scanning', currentDir: 'Running processes...', filesFound: 0, filesScanned: 0, totalDirs: 5, dirsDone: 1 })
  results.push(...scanRunningProcesses())

  await sendProgress(win, { phase: 'scanning', currentDir: 'Recent items...', filesFound: results.length, filesScanned: results.length, totalDirs: 5, dirsDone: 2 })
  results.push(...scanRecentItems())

  await sendProgress(win, { phase: 'scanning', currentDir: 'Prefetch files...', filesFound: results.length, filesScanned: results.length, totalDirs: 5, dirsDone: 3 })
  results.push(...scanPrefetchFiles())

  await sendProgress(win, { phase: 'analyzing', currentDir: 'Browser history...', filesFound: results.length, filesScanned: results.length, totalDirs: 5, dirsDone: 4 })

  const browserResults = await scanBrowserHistory()
  results.push(...browserResults)

  return { results, filesScanned: results.length + browserResults.length }
}

// ═══════════════════════════════════════════════
// MODE 3: CHEAT-SPECIFIC SEARCH (expanded)
// ═══════════════════════════════════════════════

const CHEAT_SOFTWARE_NAMES: Record<string, string[]> = {
  'Nightfall': ['nightfall', 'nightfall cheat', 'nightfall loader'],
  'DMA': ['dma', 'dma card', 'dma cheat', 'dma firmware'],
  '0XCheat': ['0xcheat', '0x cheat', 'oxcheat'],
  '1337 Cheat': ['1337', '1337 cheat', 'leet cheat'],
  'NoleetCheats': ['noleet', 'noleetcheats', 'noleet cheat'],
}

const _walkCache = new Map<string, string[]>()

function getDeepWalkEntries(dirPath: string, maxDepth = 2): string[] {
  const key = `${dirPath}:${maxDepth}`
  const cached = _walkCache.get(key)
  if (cached !== undefined) return cached

  const entries: string[] = []
  function walk(d: string, depth: number) {
    if (depth > maxDepth) return
    try {
      const dirEntries = fs.readdirSync(d, { withFileTypes: true })
      for (const entry of dirEntries) {
        const fullPath = path.join(d, entry.name)
        entries.push(fullPath)
        if (entry.isDirectory() && !entry.name.startsWith('.')) {
          walk(fullPath, depth + 1)
        }
      }
    } catch { /* skip */ }
  }
  walk(dirPath, 0)

  _walkCache.set(key, entries)
  return entries
}

function scanForCheatFiles(cheatName: string, keywords: string[]): ScanResult[] {
  const results: ScanResult[] = []
  const searchDirs = getScanPaths().slice(0, 8) // Top-level user paths

  // Collect all entries once, then check against all cheat keywords
  const allEntries: string[] = []
  for (const dir of searchDirs) {
    if (!fs.existsSync(dir)) continue
    try {
      allEntries.push(...getDeepWalkEntries(dir, 2))
    } catch { /* skip */ }
  }

  for (const entryPath of allEntries) {
    const lower = path.basename(entryPath).toLowerCase()
    const matches: string[] = []
    for (const keyword of keywords) {
      if (lower.includes(keyword)) matches.push(`cheat:${cheatName.toLowerCase()} → ${keyword}`)
    }
    // Also match against the full cheat DB
    const sigMatches = matchKnownCheat(lower)
    matches.push(...sigMatches)

    if (matches.length > 0) {
      try {
        const stat = fs.statSync(entryPath)
        results.push({
          path: entryPath,
          fileName: stat.isDirectory() ? path.basename(entryPath) + '/' : path.basename(entryPath),
          type: 'file',
          risk: matches.length >= 2 ? 'high' : 'medium',
          matches, size: stat.size, modifiedAt: stat.mtime.toISOString(),
        })
      } catch { /* skip */ }
    }
  }

  return results
}

function scanRegistryForCheats(): ScanResult[] {
  const results: ScanResult[] = []

  for (const keyPath of REGISTRY_SCAN_KEYS) {
    try {
      const output = execSync(`reg query "${keyPath}" /s 2>nul`, { encoding: 'utf-8', timeout: 5000 })
      if (!output || output.trim().length === 0) continue

      const lower = output.toLowerCase()

      // Check against KNOWN cheat DB
      for (const keyword of ALL_CHEAT_KEYWORDS) {
        if (lower.includes(keyword.toLowerCase())) {
          const safeKey = keyword.slice(0, 40)
          results.push({
            path: keyPath, fileName: `Registry: ${safeKey}`, type: 'registry',
            risk: 'high', matches: [`registry:${safeKey} found`], size: 0, modifiedAt: new Date().toISOString(),
          })
          break // one match per key is enough
        }
      }
    } catch { /* skip */ }
  }

  return results
}

async function runCheatScan(win: BrowserWindow | null): Promise<{ results: ScanResult[]; filesScanned: number }> {
  const results: ScanResult[] = []
  const cheatNames = Object.keys(CHEAT_SOFTWARE_NAMES)
  let filesScanned = 0

  for (let i = 0; i < cheatNames.length; i++) {
    const cheatName = cheatNames[i]
    const keywords = CHEAT_SOFTWARE_NAMES[cheatName]

    await sendProgress(win, { phase: 'scanning', currentDir: `Searching for ${cheatName}...`, filesFound: results.length, filesScanned, totalDirs: cheatNames.length + 2, dirsDone: i + 1 })

    const fileResults = scanForCheatFiles(cheatName, keywords)
    results.push(...fileResults)
    filesScanned += fileResults.length
  }

  const cheatKw = Object.values(CHEAT_SOFTWARE_NAMES).flat()
  const browserResults = await scanBrowserHistory(cheatKw)
  results.push(...browserResults)

  await sendProgress(win, { phase: 'analyzing', currentDir: 'Checking registry...', filesFound: results.length, filesScanned, totalDirs: cheatNames.length + 2, dirsDone: cheatNames.length + 1 })
  const registryResults = scanRegistryForCheats()
  results.push(...registryResults)

  return { results, filesScanned: results.length }
}

// ═══════════════════════════════════════════════
// MODE 4: DMA DETECTION
// ═══════════════════════════════════════════════

const KNOWN_DMA_VENDORS = [
  { name: 'Xilinx', ids: ['10ee'] },
  { name: 'Altera/Intel FPGA', ids: ['1172'] },
  { name: 'Lattice Semiconductor', ids: ['1204'] },
  { name: 'FTDI (USB-FPGA bridge)', ids: ['0403'] },
  { name: 'Texas Instruments (FPGA)', ids: ['104c'] },
]

function queryPnpDevices(filter: string): string {
  return execCmd(
    `wmic path Win32_PnPEntity where "${filter}" get DeviceID,Name,PNPDeviceID /format:csv 2>nul`,
    `powershell "Get-PnpDevice | Where-Object { $_.Class -eq '${filter.replace(/PNPClass='/g, '').replace(/'/g, '')}' } | Format-List"`,
  )
}

function scanDmaDevices(): ScanResult[] {
  const results: ScanResult[] = []

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

  // Check all scan paths for DMA software
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
          } catch { /* skip */ }
        }
      }
    } catch { /* skip */ }
  }

  // Check system drivers for DMA
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
  } catch { /* skip */ }

  return results
}

function scanDmaRegistry(): ScanResult[] {
  const results: ScanResult[] = []
  const svcPath = 'HKLM\\SYSTEM\\CurrentControlSet\\Services'

  for (const term of ['dma', 'fpga', 'pcileech', 'fuser', 'leech']) {
    try {
      const out = execSync(`reg query "${svcPath}" /s /f "${term}" 2>nul`, { encoding: 'utf-8', timeout: 5000 })
      if (out.trim().length > 0) {
        results.push({ path: svcPath, fileName: `Registry: ${term.toUpperCase()}-related services`, type: 'registry', risk: 'high', matches: [`registry:${term} service(s) found`], size: 0, modifiedAt: new Date().toISOString() })
      }
    } catch { /* skip */ }
  }

  return results
}

async function runDmaScan(win: BrowserWindow | null): Promise<{ results: ScanResult[]; filesScanned: number }> {
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

// ═══════════════════════════════════════════════
// MAIN IPC HANDLER
// ═══════════════════════════════════════════════

export function registerScanHandlers() {
  ipcMain.handle('start-scan', async (event, mode: ScanMode = 'files') => {
    const startTime = Date.now()
    const win = BrowserWindow.fromWebContents(event.sender)
    let results: ScanResult[] = []
    let filesScanned = 0

    switch (mode) {
      case 'files':     ({ results, filesScanned } = await runFileScan(win)); break
      case 'processes': ({ results, filesScanned } = await runProcessScan(win)); break
      case 'cheats':    ({ results, filesScanned } = await runCheatScan(win)); break
      case 'dma':       ({ results, filesScanned } = await runDmaScan(win)); break
    }

    const highRiskCount = results.filter(r => r.risk === 'high').length

    sendProgress(win, { phase: 'done', currentDir: '', filesFound: results.length, filesScanned, totalDirs: 4, dirsDone: 4 })

    return {
      results,
      summary: {
        totalScanned: filesScanned,
        suspiciousFiles: results.length,
        highRiskCount,
        scanTimeMs: Date.now() - startTime,
      },
    } as ScanResponse
  })
}
