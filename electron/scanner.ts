import { ipcMain, BrowserWindow } from 'electron'
import fs from 'fs'
import path from 'path'
import os from 'os'
import { execSync } from 'child_process'

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

// ── Config (env-var aware paths) ───────────────

const TARGET_EXTENSIONS = new Set([
  '.js', '.exe', '.dll', '.bat', '.ps1', '.vbs', '.ahk',
  '.lua', '.py', '.cs', '.cpp', '.c', '.h', '.cfg', '.ini',
  '.txt', '.log', '.json', '.xml', '.sys', '.drv',
])

const SUSPICIOUS_KEYWORDS = [
  'nightfall', 'cheat', 'hack', 'mod menu', 'inject', 'injector',
  'bypass', 'predator', 'hook', 'dll inject', 'memory hack',
  'trainer', 'crack', 'exploit', 'modloader', 'script hook',
  'unknowncheats', 'guided hacking', 'mpgh', 'aimbot', 'wallhack',
  'esp hack', 'triggerbot', 'silent aim', 'crosshair',
  'fuser', 'pcileech', 'screamer', 'dma', 'fpga',
  '0xcheat', '1337 cheat', 'noleetcheats',
  'kmem', 'memprocfs', 'vmm', 'winpmem',
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

const SCAN_DIRS = [
  path.join(os.homedir(), 'Downloads'),
  path.join(os.homedir(), 'Desktop'),
  path.join(os.homedir(), 'Documents'),
  path.join(os.homedir(), 'AppData', 'Local'),
  path.join(os.homedir(), 'AppData', 'Roaming'),
]

const BROWSER_DIRS = [
  path.join(os.homedir(), 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'History'),
  path.join(os.homedir(), 'AppData', 'Local', 'Yandex', 'YandexBrowser', 'User Data', 'Default', 'History'),
  path.join(os.homedir(), 'AppData', 'Roaming', 'Opera Software', 'Opera Stable', 'History'),
]

// Use env vars — supports non-C: drives
const _PF = process.env.ProgramFiles || 'C:\\Program Files'
const _PF86 = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)'
const _PD = process.env.ProgramData || 'C:\\ProgramData'
const _WR = process.env.SystemRoot || 'C:\\Windows'

const CHEAT_SCAN_DIRS = [
  path.join(os.homedir(), 'AppData', 'Local'),
  path.join(os.homedir(), 'AppData', 'Roaming'),
  path.join(os.homedir(), 'Downloads'),
  path.join(os.homedir(), 'Desktop'),
  path.join(os.homedir(), 'Documents'),
  _PD,
  _PF,
  _PF86,
]

const CHEAT_KEYWORDS = [
  'nightfall', 'dma', '0xcheat', '1337', 'noleet', 'noleetcheats',
  'fuser', 'pcileech', 'screamer', 'fpga', 'dma card',
  'cheat loader', 'injector', 'mod menu',
  'kmem', 'memprocfs',
]

const KNOWN_DMA_VENDORS = [
  { name: 'Xilinx', ids: ['10ee'] },
  { name: 'Altera/Intel FPGA', ids: ['1172'] },
  { name: 'Lattice Semiconductor', ids: ['1204'] },
  { name: 'FTDI (USB-FPGA bridge)', ids: ['0403'] },
  { name: 'Texas Instruments (FPGA)', ids: ['104c'] },
]

const KNOWN_DMA_SOFTWARE = [
  'fuser.exe', 'fuser64.exe', 'fuser_x64.exe',
  'pcileech.exe', 'pcileech64.exe',
  'screamer.exe', 'screamer_mem.exe',
  'dma.exe', 'dma64.exe',
  'fpga.exe',
  'leechcore.dll', 'leechcore64.dll',
  'vmm.dll', 'vmm64.dll',
  'coremap.exe',
  'kmem.exe',
  'memprocfs.exe', 'winpmem.exe',
  'FTD3XX.dll', 'ftd2xx.dll',
]

// ── Helpers ────────────────────────────────────

function getFileRiskLevel(fileName: string, matches: string[]): 'high' | 'medium' | 'low' {
  const ext = path.extname(fileName).toLowerCase()
  const highRiskExts = ['.exe', '.dll', '.sys', '.drv', '.bat', '.ps1', '.vbs', '.ahk']
  const mediumRiskExts = ['.js', '.lua', '.py', '.cs']

  const hasHighKeyword = matches.some(k =>
    ['dll inject', 'memory hack', 'injector', 'aimbot', 'wallhack', 'triggerbot', 'dma', 'fpga', 'pcileech'].includes(k)
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

function sendProgress(win: BrowserWindow | null, data: ScanProgress) {
  win?.webContents.send('scan-progress', data)
}

// ── exec helper with PowerShell fallback ──────

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

// ═══════════════════════════════════════════════
// MODE 1: FILE SCAN
// ═══════════════════════════════════════════════

async function scanFile(filePath: string): Promise<ScanResult | null> {
  try {
    const stat = fs.statSync(filePath)
    if (!stat.isFile() || stat.size > 5 * 1024 * 1024) return null

    const fileName = path.basename(filePath).toLowerCase()
    const matches: string[] = []

    for (const keyword of SUSPICIOUS_KEYWORDS) {
      if (fileName.includes(keyword.toLowerCase())) matches.push(`filename:${keyword}`)
    }
    for (const pattern of SUSPICIOUS_PATTERNS) {
      if (pattern.test(path.basename(filePath))) matches.push(`pattern:${pattern.source.replace(/\\/g, '')}`)
    }

    const ext = path.extname(filePath).toLowerCase()
    const textExts = new Set(['.txt', '.log', '.json', '.xml', '.cfg', '.ini', '.js', '.lua', '.py', '.cs', '.bat', '.ps1', '.vbs', '.ahk'])
    if (textExts.has(ext) && stat.size < 512 * 1024) {
      try {
        const content = fs.readFileSync(filePath, 'utf-8').toLowerCase()
        for (const keyword of SUSPICIOUS_KEYWORDS) {
          if (content.includes(keyword)) matches.push(`content:${keyword}`)
        }
      } catch { /* binary */ }
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
  const kw = keywords || SUSPICIOUS_KEYWORDS
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

  for (let i = 0; i < SCAN_DIRS.length; i++) {
    const dir = SCAN_DIRS[i]
    if (!fs.existsSync(dir)) continue

    sendProgress(win, { phase: 'scanning', currentDir: dir, filesFound: results.length, filesScanned, totalDirs: SCAN_DIRS.length, dirsDone: i })

    const files: string[] = []
    for (const filePath of walkDir(dir)) files.push(filePath)

    for (const filePath of files) {
      filesScanned++
      const r = await scanFile(filePath)
      if (r) results.push(r)
      if (filesScanned % 20 === 0) {
        sendProgress(win, { phase: 'scanning', currentDir: dir, filesFound: results.length, filesScanned, totalDirs: SCAN_DIRS.length, dirsDone: i })
      }
    }
  }

  return { results, filesScanned }
}

// ═══════════════════════════════════════════════
// MODE 2: PROCESS SCAN
// ═══════════════════════════════════════════════

const SUSPICIOUS_PROCESS_NAMES = [
  'cheat', 'trainer', 'inject', 'hook', 'bypass',
  'fuser', 'pcileech', 'screamer', 'dma',
  'memprocfs', 'kmem', 'winpmem',
  'wireshark', 'process hacker', 'processhacker',
  'x64dbg', 'ollydbg', 'cheat engine', 'cheatengine',
  'reclass', 'ida', 'ghidra', 'unknowncheats', 'dnspy',
]

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

        const matches: string[] = []
        for (const keyword of SUSPICIOUS_PROCESS_NAMES) {
          if (name.includes(keyword)) matches.push(`process:${keyword}`)
        }

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
      const lower = item.toLowerCase()
      const matches: string[] = []
      for (const keyword of SUSPICIOUS_PROCESS_NAMES) {
        if (lower.includes(keyword)) matches.push(`recent:${keyword}`)
      }
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
      const lower = file.toLowerCase()
      const matches: string[] = []
      for (const keyword of SUSPICIOUS_PROCESS_NAMES) {
        if (lower.includes(keyword)) matches.push(`prefetch:${keyword} last run`)
      }
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

  sendProgress(win, { phase: 'scanning', currentDir: 'Running processes...', filesFound: 0, filesScanned: 0, totalDirs: 3, dirsDone: 0 })

  results.push(...scanRunningProcesses())

  sendProgress(win, { phase: 'scanning', currentDir: 'Recent items...', filesFound: results.length, filesScanned: results.length, totalDirs: 3, dirsDone: 1 })
  results.push(...scanRecentItems())

  sendProgress(win, { phase: 'scanning', currentDir: 'Prefetch files...', filesFound: results.length, filesScanned: results.length, totalDirs: 3, dirsDone: 2 })
  results.push(...scanPrefetchFiles())

  sendProgress(win, { phase: 'analyzing', currentDir: 'Browser history...', filesFound: results.length, filesScanned: results.length, totalDirs: 3, dirsDone: 3 })

  const browserResults = await scanBrowserHistory()
  const processHits = browserResults.filter(r => r.matches.some(m => SUSPICIOUS_PROCESS_NAMES.some(p => m.includes(p))))
  results.push(...processHits)

  return { results, filesScanned: results.length }
}

// ═══════════════════════════════════════════════
// MODE 3: CHEAT-SPECIFIC SEARCH
// ═══════════════════════════════════════════════

const CHEAT_SOFTWARE_NAMES: Record<string, string[]> = {
  'Nightfall': ['nightfall', 'nightfall cheat', 'nightfall loader'],
  'DMA': ['dma', 'dma card', 'dma cheat', 'dma firmware'],
  '0XCheat': ['0xcheat', '0x cheat', 'oxcheat'],
  '1337 Cheat': ['1337', '1337 cheat', 'leet cheat'],
  'NoleetCheats': ['noleet', 'noleetcheats', 'noleet cheat'],
}

function scanForCheatFiles(cheatName: string, keywords: string[]): ScanResult[] {
  const results: ScanResult[] = []
  const searchDirs = [
    path.join(os.homedir(), 'Downloads'), path.join(os.homedir(), 'Desktop'),
    path.join(os.homedir(), 'Documents'), path.join(os.homedir(), 'AppData', 'Local'),
    path.join(os.homedir(), 'AppData', 'Roaming'), _PD,
  ]

  for (const dir of searchDirs) {
    if (!fs.existsSync(dir)) continue
    try {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const lower = entry.name.toLowerCase()
        const matches: string[] = []
        for (const keyword of keywords) {
          if (lower.includes(keyword)) matches.push(`cheat:${cheatName.toLowerCase()} → ${keyword}`)
        }

        if (matches.length > 0) {
          const fullPath = path.join(dir, entry.name)
          try {
            const stat = fs.statSync(fullPath)
            results.push({ path: fullPath, fileName: entry.name, type: 'file', risk: 'high', matches, size: stat.size, modifiedAt: stat.mtime.toISOString() })
          } catch { /* skip */ }
        }

        // 1 level deep in subdirs
        if (entry.isDirectory() && !entry.name.startsWith('.')) {
          try {
            for (const sub of fs.readdirSync(fullPath, { withFileTypes: true })) {
              const subLower = sub.name.toLowerCase()
              const subMatches: string[] = []
              for (const keyword of keywords) {
                if (subLower.includes(keyword)) subMatches.push(`cheat:${cheatName.toLowerCase()} → ${keyword}`)
              }
              if (subMatches.length > 0) {
                try {
                  const stat = fs.statSync(path.join(fullPath, sub.name))
                  results.push({ path: path.join(fullPath, sub.name), fileName: path.join(entry.name, sub.name), type: 'file', risk: 'high', matches: subMatches, size: stat.size, modifiedAt: stat.mtime.toISOString() })
                } catch { /* skip */ }
              }
            }
          } catch { /* skip */ }
        }
      }
    } catch { /* skip */ }
  }

  return results
}

function scanRegistryForCheats(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    const output = execSync('reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall" /s 2>nul', { encoding: 'utf-8', timeout: 3000 })
    const lower = output.toLowerCase()
    for (const [cheatName, keywords] of Object.entries(CHEAT_SOFTWARE_NAMES)) {
      const matches: string[] = []
      for (const keyword of keywords) {
        if (lower.includes(keyword)) matches.push(`registry:${cheatName.toLowerCase()} installed`)
      }
      if (matches.length > 0) results.push({ path: 'HKCU\\...\\Uninstall', fileName: `Registry: ${cheatName}`, type: 'registry', risk: 'high', matches, size: 0, modifiedAt: new Date().toISOString() })
    }
  } catch { /* skip */ }

  try {
    const output = execSync('reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU" 2>nul', { encoding: 'utf-8', timeout: 3000 })
    const lower = output.toLowerCase()
    for (const [cheatName, keywords] of Object.entries(CHEAT_SOFTWARE_NAMES)) {
      const matches: string[] = []
      for (const keyword of keywords) {
        if (lower.includes(keyword)) matches.push(`runmru:${cheatName.toLowerCase()} executed`)
      }
      if (matches.length > 0) results.push({ path: 'HKCU\\...\\RunMRU', fileName: `RunMRU: ${cheatName}`, type: 'registry', risk: 'high', matches, size: 0, modifiedAt: new Date().toISOString() })
    }
  } catch { /* skip */ }

  return results
}

async function runCheatScan(win: BrowserWindow | null): Promise<{ results: ScanResult[]; filesScanned: number }> {
  const results: ScanResult[] = []
  const cheatNames = Object.keys(CHEAT_SOFTWARE_NAMES)
  let filesScanned = 0

  for (let i = 0; i < cheatNames.length; i++) {
    const cheatName = cheatNames[i]
    const keywords = CHEAT_SOFTWARE_NAMES[cheatName]

    sendProgress(win, { phase: 'scanning', currentDir: `Searching for ${cheatName}...`, filesFound: results.length, filesScanned, totalDirs: cheatNames.length, dirsDone: i })

    const fileResults = scanForCheatFiles(cheatName, keywords)
    results.push(...fileResults)
    filesScanned += fileResults.length
  }

  // Reuse scanBrowserHistory with cheat-specific keywords
  const cheatKw = Object.values(CHEAT_SOFTWARE_NAMES).flat()
  const browserResults = await scanBrowserHistory(cheatKw)
  results.push(...browserResults)
  filesScanned += browserResults.length

  sendProgress(win, { phase: 'analyzing', currentDir: 'Checking registry...', filesFound: results.length, filesScanned, totalDirs: cheatNames.length, dirsDone: cheatNames.length })

  const registryResults = scanRegistryForCheats()
  results.push(...registryResults)

  return { results, filesScanned: results.length }
}

// ═══════════════════════════════════════════════
// MODE 4: DMA DETECTION
// ═══════════════════════════════════════════════

function queryPnpDevices(filter: string): string {
  // wmic → PowerShell fallback for Windows 11 24H2+
  return execCmd(
    `wmic path Win32_PnPEntity where "${filter}" get DeviceID,Name,PNPDeviceID /format:csv 2>nul`,
    `powershell "Get-PnpDevice | Where-Object { $_.Class -eq '${filter.replace(/PNPClass='/g, '').replace(/'/g, '')}' } | Format-List"`,
  )
}

function scanDmaDevices(): ScanResult[] {
  const results: ScanResult[] = []

  // Check PCI devices
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

  // DMA software on disk
  const dmaSearchDirs = [
    path.join(os.homedir(), 'Downloads'), path.join(os.homedir(), 'Desktop'),
    path.join(os.homedir(), 'Documents'), path.join(os.homedir(), 'AppData', 'Local'),
    path.join(os.homedir(), 'AppData', 'Roaming'), _PF, _PF86,
  ]

  for (const dir of dmaSearchDirs) {
    if (!fs.existsSync(dir)) continue
    try {
      for (const entry of fs.readdirSync(dir)) {
        const lower = entry.toLowerCase()
        const matches: string[] = []
        for (const sw of KNOWN_DMA_SOFTWARE) {
          if (lower.includes(sw.replace('.exe', '').replace('.dll', ''))) matches.push(`dma-software:${sw}`)
        }
        if (lower.includes('dma') || lower.includes('fpga') || lower.includes('pcileech') || lower.includes('fuser')) {
          if (matches.length === 0) matches.push(`dma-keyword:${lower.includes('dma') ? 'dma' : lower.includes('fpga') ? 'fpga' : lower.includes('pcileech') ? 'pcileech' : 'fuser'}`)
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

  // DMA drivers in system32
  try {
    const sysDir = path.join(_WR, 'System32', 'drivers')
    if (fs.existsSync(sysDir)) {
      for (const driver of fs.readdirSync(sysDir)) {
        const lower = driver.toLowerCase()
        const matches: string[] = []
        if (lower.includes('dma') || lower.includes('fpga') || lower.includes('leech') || lower.includes('fuser')) matches.push(`driver:${driver}`)
        if (lower.includes('ftd3') || lower.includes('ftd2') || lower.includes('leeched')) matches.push(`dma-driver:${driver}`)
        if (matches.length > 0) results.push({ path: path.join(sysDir, driver), fileName: `Driver: ${driver}`, type: 'software', risk: 'high', matches, size: 0, modifiedAt: new Date().toISOString() })
      }
    }
  } catch { /* skip */ }

  return results
}

function scanDmaRegistry(): ScanResult[] {
  const results: ScanResult[] = []
  const svcPath = 'HKLM\\SYSTEM\\CurrentControlSet\\Services'

  for (const term of ['dma', 'fpga']) {
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

  sendProgress(win, { phase: 'scanning', currentDir: 'Checking PCI devices...', filesFound: 0, filesScanned: 0, totalDirs: 4, dirsDone: 0 })
  results.push(...scanDmaDevices())

  sendProgress(win, { phase: 'scanning', currentDir: 'Checking USB devices...', filesFound: results.length, filesScanned: results.length, totalDirs: 4, dirsDone: 1 })

  const usbOut = queryPnpDevices("PNPClass='USB'")
  if (usbOut && (usbOut.toLowerCase().includes('ftdi') || usbOut.toLowerCase().includes('ftd3'))) {
    results.push({ path: 'USB Devices', fileName: 'USB Device: Possible DMA interface', type: 'hardware', risk: 'medium', matches: ['usb:FTDI device (common DMA interface)'], size: 0, modifiedAt: new Date().toISOString() })
  }

  sendProgress(win, { phase: 'scanning', currentDir: 'Checking registry...', filesFound: results.length, filesScanned: results.length, totalDirs: 4, dirsDone: 2 })
  results.push(...scanDmaRegistry())

  sendProgress(win, { phase: 'analyzing', currentDir: 'Browser history for DMA...', filesFound: results.length, filesScanned: results.length, totalDirs: 4, dirsDone: 3 })

  const dmaKw = ['dma', 'fpga', 'pcileech', 'fuser', 'screamer', 'kmem']
  const browserResults = await scanBrowserHistory(dmaKw)
  results.push(...browserResults)

  return { results, filesScanned: results.length }
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

    return { results, summary: { totalScanned: filesScanned, suspiciousFiles: results.length, highRiskCount, scanTimeMs: Date.now() - startTime } } as ScanResponse
  })
}
