import { ipcMain, BrowserWindow } from 'electron'
import fs from 'fs'
import fsp from 'fs/promises'
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

import {
  evaluateYara,
  isTrustedPath,
  analyzePeHeaders,
} from './cheat-rules'

// ── Event-loop yield ──
const yieldToEventLoop = () => new Promise(resolve => setImmediate(resolve))

// ── Types ──────────────────────────────────────

export type ScanMode = 'files' | 'processes' | 'cheats' | 'dma' | 'extended' | 'network'

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
const _HOME = os.homedir()

// ── v2 Constants (from predator_scanner_v2.py) ──

interface CheatCategory {
  names: string[]
  strings: Buffer[]
  description: string
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'WARNING'
}

const SUSPICIOUS_CATEGORIES: Record<string, CheatCategory> = {
  injector: {
    names: ['inject', 'injector', 'map', 'manualmap', 'threadhijack'],
    strings: [Buffer.from('CreateRemoteThread'), Buffer.from('NtCreateThreadEx'), Buffer.from('RtlCreateUserThread'),
              Buffer.from('WriteProcessMemory'), Buffer.from('VirtualAllocEx'), Buffer.from('MapViewOfFile')],
    description: 'DLL injector — code injection into processes',
    risk: 'CRITICAL',
  },
  debugger: {
    names: ['debug', 'debugger', 'cheatengine', 'ce', 'x64dbg', 'ollydbg', 'ida'],
    strings: [Buffer.from('IsDebuggerPresent'), Buffer.from('CheckRemoteDebuggerPresent'), Buffer.from('NtQueryInformationProcess')],
    description: 'Debugger / memory hacking tool',
    risk: 'CRITICAL',
  },
  hook: {
    names: ['hook', 'detour', 'minhook', 'easyhook'],
    strings: [Buffer.from('SetWindowsHookEx'), Buffer.from('DetourAttach'), Buffer.from('MinHook'), Buffer.from('EasyHook')],
    description: 'System function hooking',
    risk: 'HIGH',
  },
  driver: {
    names: ['.sys', 'driver', 'kernel', 'km', 'ring0'],
    strings: [Buffer.from('\\Device\\'), Buffer.from('\\DosDevices\\'), Buffer.from('IoCreateDevice'), Buffer.from('PsSetCreateProcessNotifyRoutine')],
    description: 'Kernel-level driver',
    risk: 'CRITICAL',
  },
  spoofer: {
    names: ['spoofer', 'spoof', 'hwid', 'mac', 'serial', 'disk'],
    strings: [Buffer.from('HardwareID'), Buffer.from('MACAddress'), Buffer.from('DiskSerial'), Buffer.from('SMBIOS')],
    description: 'Hardware ID spoofing',
    risk: 'HIGH',
  },
  bypass: {
    names: ['bypass', 'evade', 'anti', 'block', 'disable'],
    strings: [Buffer.from('bypass'), Buffer.from('evade'), Buffer.from('anti-cheat'), Buffer.from('anti cheat')],
    description: 'Security mechanism bypass',
    risk: 'CRITICAL',
  },
  menu: {
    names: ['menu', 'gui', 'overlay', 'imgui', 'd3d'],
    strings: [Buffer.from('ImGui'), Buffer.from('Direct3D'), Buffer.from('OpenGL'), Buffer.from('overlay'), Buffer.from('esp'), Buffer.from('aimbot')],
    description: 'Game menu / overlay',
    risk: 'HIGH',
  },
  network: {
    names: ['proxy', 'vpn', 'socks', 'mitm', 'packet'],
    strings: [Buffer.from('WSASocket'), Buffer.from('connect'), Buffer.from('send'), Buffer.from('recv'), Buffer.from('socks'), Buffer.from('proxy')],
    description: 'Network manipulation tools',
    risk: 'MEDIUM',
  },
  obfuscator: {
    names: ['obf', 'pack', 'crypt', 'protect', 'vm', 'virtual'],
    strings: [Buffer.from('VMProtect'), Buffer.from('Themida'), Buffer.from('Enigma'), Buffer.from('Obsidium'), Buffer.from('Armadillo')],
    description: 'Code obfuscation / packing (hides malicious code)',
    risk: 'HIGH',
  },
}

// Protected paths — game mod directories where files should not be
const PROTECTED_PATHS = [
  path.join(_HOME, 'AppData', 'Local', 'FiveM', 'FiveM.app', 'mods'),
  path.join(_HOME, 'AppData', 'Local', 'FiveM', 'FiveM.app', 'plugins'),
  path.join(_HOME, 'AppData', 'Local', 'FiveM', 'FiveM.app', 'cache'),
  path.join(_HOME, 'AppData', 'Local', 'FiveM', 'FiveM.app', 'data'),
  path.join(_HOME, 'AppData', 'Roaming', 'CitizenFX'),
]

// Suspicious file extensions with descriptions
const SUSPICIOUS_EXTENSIONS: Record<string, string> = {
  '.dll': 'Dynamic library (possible inject)',
  '.asi': 'ASI mod GTA (game modification)',
  '.lua': 'Lua script (often used in cheats)',
  '.luac': 'Compiled Lua script',
  '.exe': 'Executable file',
  '.sys': 'System driver',
  '.bin': 'Binary file (may contain cheat config)',
  '.dat': 'Data file',
  '.cfg': 'Configuration file',
  '.ini': 'Configuration file',
  '.js': 'JavaScript (may contain cheat loader)',
  '.ahk': 'AutoHotkey script',
}

// v2 scan config
const SCAN_CONFIG = {
  SCAN_DEPTH: 3,
  MAX_FILE_SIZE: 100 * 1024 * 1024,
  MIN_FILE_SIZE: 1024,
  SUSPICIOUS_AGE_DAYS: 30,
  ENTROPY_THRESHOLD: 7.5,
}

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
  path.join(_HOME, 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'History'),
  path.join(_HOME, 'AppData', 'Local', 'Yandex', 'YandexBrowser', 'User Data', 'Default', 'History'),
  path.join(_HOME, 'AppData', 'Roaming', 'Opera Software', 'Opera Stable', 'History'),
]

// ── v2 Helpers ─────────────────────────────────

/** Shannon entropy (0–8). High = possibly packed / encrypted. O(n) single-pass. */
function calculateEntropy(data: Buffer): number {
  if (!data || data.length === 0) return 0
  const freq = new Array(256).fill(0)
  for (const b of data) freq[b]++
  const len = data.length
  let entropy = 0
  for (const count of freq) {
    if (count > 0) {
      const p = count / len
      entropy -= p * Math.log2(p)
    }
  }
  return entropy
}

/** Extract ASCII + Unicode strings from a binary file */
function scanStrings(filepath: string, maxSize = 5 * 1024 * 1024): string[] {
  const strings: string[] = []
  try {
    const stat = fs.statSync(filepath)
    if (stat.size > maxSize) return strings

    const fd = fs.openSync(filepath, 'r')
    const data = Buffer.alloc(Math.min(stat.size, maxSize))
    fs.readSync(fd, data, 0, data.length, 0)
    fs.closeSync(fd)

    // ASCII strings (4+ readable chars 0x20–0x7E)
    let ascii = ''
    for (const b of data) {
      if (b >= 0x20 && b <= 0x7E) {
        ascii += String.fromCharCode(b)
      } else {
        if (ascii.length >= 4) strings.push(ascii)
        ascii = ''
      }
    }
    if (ascii.length >= 4) strings.push(ascii)

    // Unicode UTF-16LE strings (4+ chars with \0 interleave)
    let uniBuf: number[] = []
    for (let i = 0; i < data.length - 1; i += 2) {
      if (data[i] >= 0x20 && data[i] <= 0x7E && data[i + 1] === 0x00) {
        uniBuf.push(data[i])
      } else {
        if (uniBuf.length >= 4) strings.push(String.fromCharCode(...uniBuf))
        uniBuf = []
      }
    }
    if (uniBuf.length >= 4) strings.push(String.fromCharCode(...uniBuf))
  } catch { /* skip */ }
  return strings
}

/** Cached digital signature check via PowerShell Get-AuthenticodeSignature */
const _sigCache = new Map<string, boolean>()

function checkDigitalSignature(filepath: string): boolean {
  const cached = _sigCache.get(filepath)
  if (cached !== undefined) return cached
  try {
    const out = execSync(
      `powershell -Command "(Get-AuthenticodeSignature '${filepath.replace(/'/g, "''")}').Status"`,
      { encoding: 'utf-8', timeout: 5000 },
    )
    const valid = out.includes('Valid')
    _sigCache.set(filepath, valid)
    return valid
  } catch {
    _sigCache.set(filepath, false)
    return false
  }
}

interface HeuristicResult {
  riskScore: number
  suspicions: string[]
}

/** Heuristic file analysis — entropy, signatures, name, age, protected paths */
function heuristicFileScan(filepath: string): HeuristicResult | null {
  try {
    const stat = fs.statSync(filepath)
    if (!stat.isFile() || stat.size > SCAN_CONFIG.MAX_FILE_SIZE || stat.size < SCAN_CONFIG.MIN_FILE_SIZE) {
      return null
    }

    const fileName = path.basename(filepath).toLowerCase()
    const ext = path.extname(filepath).toLowerCase()
    const ageDays = (Date.now() - stat.mtimeMs) / (1000 * 60 * 60 * 24)
    const suspicions: string[] = []
    let riskScore = 0

    // 1. Extension check
    if (SUSPICIOUS_EXTENSIONS[ext]) {
      suspicions.push(`Extension ${ext}: ${SUSPICIOUS_EXTENSIONS[ext]}`)
      riskScore += 20
    }

    // 2. Name check against categories
    for (const [catName, cat] of Object.entries(SUSPICIOUS_CATEGORIES)) {
      for (const name of cat.names) {
        if (fileName.includes(name)) {
          suspicions.push(`Name → [${catName}]: ${cat.description}`)
          riskScore += 40
          break
        }
      }
    }

    // 3. Age check (recently created = suspicious)
    if (ageDays < SCAN_CONFIG.SUSPICIOUS_AGE_DAYS) {
      suspicions.push(`Recently created (${Math.round(ageDays)} days ago)`)
      riskScore += 15
    }

    // v3.0: Whitelist check — reduce score for trusted paths
    if (isTrustedPath(filepath)) {
      riskScore = Math.max(riskScore - 30, 0) // Trusted path = much less suspicious
    }

    // 4. Binary analysis (exe, dll, asi, sys)
    const binaryExts = new Set(['.exe', '.dll', '.asi', '.sys', '.drv'])
    if (binaryExts.has(ext) && stat.size >= 4096 && stat.size < 50 * 1024 * 1024) {
      const fd = fs.openSync(filepath, 'r')
      const sampleSize = Math.min(65536, stat.size)
      const sample = Buffer.alloc(sampleSize)
      fs.readSync(fd, sample, 0, sampleSize, 0)
      fs.closeSync(fd)

      // Entropy analysis (single-pass O(n))
      const entropy = calculateEntropy(sample)
      if (entropy > SCAN_CONFIG.ENTROPY_THRESHOLD) {
        suspicions.push(`High entropy (${entropy.toFixed(2)}) — possibly packed/encrypted`)
        riskScore += 30
      }

      // String signature analysis (ASCII + Unicode)
      const strings = scanStrings(filepath)
      const stringsLower = strings.map(s => s.toLowerCase())

      // v3.0: YARA-like rule evaluation (must be after stringsLower)
      const yaraMatches = evaluateYara(sample, stringsLower)
      for (const yMatch of yaraMatches) {
        suspicions.push(`YARA [${yMatch.ruleName}]: ${yMatch.description}`)
        riskScore += yMatch.risk === 'CRITICAL' ? 60 : yMatch.risk === 'HIGH' ? 40 : 20
      }

      // v3.0: PE analysis
      if (ext === '.exe' || ext === '.dll' || ext === '.sys') {
        const peInfo = analyzePeHeaders(filepath)
        if (peInfo && peInfo.isValidPe && peInfo.isSuspicious) {
          if (peInfo.suspiciousSections.length > 0) {
            suspicions.push(`PE: Unusual sections: ${peInfo.suspiciousSections.join(', ')}`)
            riskScore += 25
          }
          if (peInfo.entryPointInSuspiciousSection) {
            suspicions.push('PE: Entry point in unusual section')
            riskScore += 20
          }
          if (peInfo.relocsStripped) {
            suspicions.push('PE: Relocations stripped (suggests packed/ASLR disabled)')
            riskScore += 15
          }
        }
      }

      // Category signature analysis (ASCII + Unicode)
      for (const [catName, cat] of Object.entries(SUSPICIOUS_CATEGORIES)) {
        const found: string[] = []
        for (const sigBuf of cat.strings) {
          const sigStr = sigBuf.toString().toLowerCase()
          if (stringsLower.some(s => s.includes(sigStr))) {
            found.push(sigStr)
          }
        }
        if (found.length > 0) {
          suspicions.push(`Signatures [${catName}]: ${found.slice(0, 3).join(', ')}`)
          riskScore += 50
        }
      }

      // Cached digital signature check
      const hasSig = checkDigitalSignature(filepath)
      if (hasSig) {
        riskScore -= 10 // Signed = less suspicious
      } else {
        suspicions.push('No digital signature')
        riskScore += 20
      }
    }

    // 5. Check if in a protected path
    for (const protectedPath of PROTECTED_PATHS) {
      if (filepath.toLowerCase().includes(protectedPath.toLowerCase())) {
        suspicions.push(`File in protected folder: ${protectedPath}`)
        riskScore += 25
        break
      }
    }

    if (riskScore === 0) return null
    return { riskScore, suspicions }
  } catch {
    return null
  }
}

function riskScoreToLevel(score: number): 'high' | 'medium' | 'low' {
  if (score > 80) return 'high'
  if (score > 50) return 'medium'
  return 'low'
}

/** Deduplication set for findings */
const _findingDedup = new Set<string>()

function addFindingDedup(key: string): boolean {
  if (_findingDedup.has(key)) return false
  _findingDedup.add(key)
  return true
}

// ── Standard helpers ───────────────────────────

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

// ── Async directory walker ──
async function* walkDirAsync(dirPath: string): AsyncGenerator<string> {
  try {
    const entries = await fsp.readdir(dirPath, { withFileTypes: true })
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name)
      if (entry.isDirectory()) {
        if (!entry.name.startsWith('.') && entry.name !== 'node_modules' && entry.name !== 'Temp') {
          await yieldToEventLoop()
          yield* walkDirAsync(fullPath)
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase()
        if (TARGET_EXTENSIONS.has(ext)) yield fullPath
      }
    }
  } catch { /* skip */ }
}

async function sendProgress(win: BrowserWindow | null, data: ScanProgress) {
  win?.webContents.send('scan-progress', data)
  await yieldToEventLoop()
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
    .replace(/_\*\.exe$/i, '')
    .replace(/\*\.exe$/i, '')
)
const _FILE_NAMES = KNOWN_CHEAT_FILES.map(n => n.toLowerCase())
const _LUA_NAMES = KNOWN_LUA_SCRIPTS.map(n => n.toLowerCase())
const _FOLDER_NAMES = KNOWN_CHEAT_FOLDERS.map(n => n.toLowerCase())

const _cheatNameCache = new Map<string, string[]>()

function matchKnownCheat(name: string): string[] {
  const lower = name.toLowerCase()
  const cached = _cheatNameCache.get(lower)
  if (cached !== undefined) return cached

  const matches: string[] = []
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
    const stat = await fsp.stat(filePath)
    if (!stat.isFile() || stat.size > 5 * 1024 * 1024) return null

    const fileName = path.basename(filePath)
    const matches: string[] = []

    const sigMatches = matchKnownCheat(fileName)
    matches.push(...sigMatches)

    for (const pattern of SUSPICIOUS_PATTERNS) {
      if (pattern.test(fileName)) matches.push(`pattern:${pattern.source.replace(/\\/g, '')}`)
    }

    const ext = path.extname(filePath).toLowerCase()
    const textExts = new Set(['.txt', '.log', '.json', '.xml', '.cfg', '.ini', '.js', '.lua', '.py', '.cs', '.bat', '.ps1', '.vbs', '.ahk', '.luac'])
    if (textExts.has(ext) && stat.size < 512 * 1024) {
      try {
        const content = (await fsp.readFile(filePath, 'utf-8')).toLowerCase()
        for (const keyword of ALL_CHEAT_KEYWORDS) {
          if (content.includes(keyword)) matches.push(`content:${keyword}`)
        }
      } catch { /* binary */ }
    }

    const binaryExts = new Set(['.exe', '.dll', '.sys', '.drv', '.asi', '.luac'])
    if (binaryExts.has(ext) && stat.size >= 1024 && stat.size < 50 * 1024 * 1024) {
      try {
        const buffer = await fsp.readFile(filePath)
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
      await fsp.access(historyPath)
      const stat = await fsp.stat(historyPath)
      if (stat.size > 10 * 1024 * 1024) continue

      const content = (await fsp.readFile(historyPath, 'utf-8')).toLowerCase()
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
    await yieldToEventLoop()
  }

  return results
}

async function runFileScan(win: BrowserWindow | null): Promise<{ results: ScanResult[]; filesScanned: number }> {
  const results: ScanResult[] = []
  let filesScanned = 0
  const scanDirs = getScanPaths()

  for (let i = 0; i < scanDirs.length; i++) {
    const dir = scanDirs[i]
    try {
      await fsp.access(dir)
    } catch {
      await sendProgress(win, { phase: 'scanning', currentDir: `${dir} (skipped)`, filesFound: results.length, filesScanned, totalDirs: scanDirs.length, dirsDone: i + 1 })
      continue
    }

    await sendProgress(win, { phase: 'scanning', currentDir: dir, filesFound: results.length, filesScanned, totalDirs: scanDirs.length, dirsDone: i + 1 })

    for await (const filePath of walkDirAsync(dir)) {
      filesScanned++
      const r = await scanFile(filePath)
      if (r) results.push(r)
      await yieldToEventLoop()
      if (filesScanned % 10 === 0) {
        await sendProgress(win, { phase: 'scanning', currentDir: dir, filesFound: results.length, filesScanned, totalDirs: scanDirs.length, dirsDone: i + 1 })
      }
    }

    await sendProgress(win, { phase: 'scanning', currentDir: dir, filesFound: results.length, filesScanned, totalDirs: scanDirs.length, dirsDone: i + 1 })
  }

  return { results, filesScanned }
}

// ═══════════════════════════════════════════════
// MODE 2: PROCESS SCAN
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
  const recentDir = path.join(_HOME, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Recent')

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

/** v2: Advanced process scan — checks loaded DLLs and modules via PowerShell */
function scanRunningProcessesV2(): ScanResult[] {
  const results: ScanResult[] = []

  // Standard process scan first
  const basicResults = scanRunningProcesses()
  for (const r of basicResults) {
    if (addFindingDedup(`proc:${r.fileName}`)) results.push(r)
  }

  // Advanced: check process modules for suspicious DLLs
  try {
    const psOut = execSync(
      `powershell -Command "Get-Process | Where-Object { $_.Modules } | Select-Object Name, Id, @{N='Mods';E={$_.Modules | Select -Expand ModuleName}} | ConvertTo-Json -Depth 3"`,
      { encoding: 'utf-8', timeout: 10000 },
    )

    if (!psOut || psOut.trim().length < 5) return results

    const parsed = JSON.parse(psOut)
    const processes = Array.isArray(parsed) ? parsed : [parsed]

    for (const proc of processes) {
      const procName = (proc.Name || '').toLowerCase()
      const modules: string[] = proc.Mods || []

      for (const modName of modules) {
        if (!modName || typeof modName !== 'string') continue
        const modLower = modName.toLowerCase()

        for (const [catName, cat] of Object.entries(SUSPICIOUS_CATEGORIES)) {
          for (const name of cat.names) {
            if (modLower.includes(name) && addFindingDedup(`mod:${procName}:${modLower}`)) {
              results.push({
                path: `process:${proc.Name} (PID: ${proc.Id})`,
                fileName: `Module: ${modName}`,
                type: 'process',
                risk: cat.risk === 'CRITICAL' || cat.risk === 'HIGH' ? 'high' : 'medium',
                matches: [`module:${name} (${catName})`, `process:${procName}`],
                size: 0,
                modifiedAt: new Date().toISOString(),
              })
            }
          }
        }
      }
    }
  } catch { /* PowerShell failed */ }

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
// MODE 3: CHEAT-SPECIFIC SEARCH
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
  const searchDirs = getScanPaths().slice(0, 8)

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
      for (const keyword of ALL_CHEAT_KEYWORDS) {
        if (lower.includes(keyword.toLowerCase())) {
          const safeKey = keyword.slice(0, 40)
          results.push({
            path: keyPath, fileName: `Registry: ${safeKey}`, type: 'registry',
            risk: 'high', matches: [`registry:${safeKey} found`], size: 0, modifiedAt: new Date().toISOString(),
          })
          break
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
// MODE 5: EXTENDED — v2 FULL SYSTEM SCAN
// Based on predator_scanner_v2.py:
//   8 phases with heuristic analysis, entropy,
//   category-based signatures, risk scoring,
//   deduplication, digital signature verification.
// ═══════════════════════════════════════════════

const EXTENDED_CHEAT_KEYWORDS: string[] = [
  'eulen', 'redengine', 'skript.gg', 'impulse.one',
  'luna', 'paragon', 'ozark', 'cherax', 'stand.gg',
  '2take1.menu', 'modest', 'kiddions', 'majesty.rp',
  'menyoo', 'simpletrainer', 'nativeui',
  'xenos', 'extremeinjector', 'manualmap',
  'fivem bypass', 'rockstar bypass', 'ac bypass',
  'rpchanger', 'hwid spoofer', 'mac spoofer',
  'dma', 'fpga', 'pcileech', 'fuser', 'screamer',
  'leechcore', 'memprocfs', 'vmm', 'kmem', 'winpmem',
  'process hacker', 'dnspy', 'ollydbg', 'x64dbg', 'ida',
  'aimbot', 'wallhack', 'esp', 'triggerbot',
  'norecoil', 'godmode', 'teleport', 'moneydrop',
  'recovery', 'unlock all', 'mod menu',
  // v2 category keywords
  'inject', 'injector', 'hook', 'detour', 'bypass', 'evade',
  'spoofer', 'hwid', 'obfuscator', 'vmprotect', 'themida',
]

/** v2: Deep registry scan — checks all autorun paths against categories */
function scanRegistryDeepV2(): ScanResult[] {
  const results: ScanResult[] = []

  const regPaths = [
    'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
    'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
    'HKCU\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',
    'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run',
    'HKLM\\SYSTEM\\CurrentControlSet\\Services',
    // v3.0: Winlogon paths
    'HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
    'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
  ]

  for (const keyPath of regPaths) {
    try {
      const output = execSync(`reg query "${keyPath}" /s 2>nul`, { encoding: 'utf-8', timeout: 5000 })
      if (!output || output.trim().length === 0) continue

      const lower = output.toLowerCase()

      for (const [catName, cat] of Object.entries(SUSPICIOUS_CATEGORIES)) {
        for (const name of cat.names) {
          if (lower.includes(name)) {
            const dedupKey = `reg-deep:${catName}:${name}`
            if (addFindingDedup(dedupKey)) {
              results.push({
                path: keyPath,
                fileName: `Registry [${catName}]: ${name}`,
                type: 'registry',
                risk: cat.risk === 'CRITICAL' ? 'high' : cat.risk === 'HIGH' ? 'high' : 'medium',
                matches: [`registry-deep:${name} (${catName})`, `risk:${cat.risk}`],
                size: 0,
                modifiedAt: new Date().toISOString(),
              })
            }
          }
        }
      }
    } catch { /* skip */ }
  }

  return results
}

/** v2: Prefetch analysis against categories */
function scanPrefetchV2(): ScanResult[] {
  const results: ScanResult[] = []
  const prefetchDir = path.join(_WR, 'Prefetch')

  try {
    if (!fs.existsSync(prefetchDir)) return results
    for (const file of fs.readdirSync(prefetchDir)) {
      if (!file.toLowerCase().endsWith('.pf')) continue
      const fileLower = file.toLowerCase()

      for (const [catName, cat] of Object.entries(SUSPICIOUS_CATEGORIES)) {
        for (const name of cat.names) {
          if (fileLower.includes(name)) {
            const dedupKey = `pf:${catName}:${file}`
            if (addFindingDedup(dedupKey)) {
              const filePath = path.join(prefetchDir, file)
              let mtime = new Date().toISOString()
              try { mtime = fs.statSync(filePath).mtime.toISOString() } catch { /* skip */ }

              results.push({
                path: filePath,
                fileName: `Prefetch [${catName}]: ${file}`,
                type: 'file',
                risk: cat.risk === 'CRITICAL' || cat.risk === 'HIGH' ? 'high' : 'medium',
                matches: [`prefetch:${name} (${catName})`, `last-run:${mtime.slice(0, 10)}`],
                size: 0,
                modifiedAt: mtime,
              })
            }
          }
        }
      }
    }
  } catch { /* skip */ }

  return results
}

/** v2: Network connection scan — suspicious ports (proxy/VPN) */
function scanNetstatV2(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    const out = execSync('netstat -ano', { encoding: 'utf-8', timeout: 8000 })
    const lines = out.split('\n')
    const suspiciousPortSet = new Set(['1080', '3128', '8080', '9050', '9150'])
    const foundPorts: string[] = []

    for (const line of lines) {
      const trimmed = line.trim()
      if (!trimmed.match(/^(TCP|UDP)/i)) continue
      const parts = trimmed.split(/\s+/)
      if (parts.length < 4) continue

      const localAddr = parts[1] || ''
      const remoteAddr = parts[2] || ''
      const pid = parts[parts.length - 1] || ''

      const port = localAddr.split(':').pop() || ''
      if (suspiciousPortSet.has(port)) {
        const dedupKey = `net-port:${port}`
        if (addFindingDedup(dedupKey)) {
          foundPorts.push(`${port} (PID: ${pid})`)
        }
      }

      // Check for connections from suspicious IP ranges (proxy/VPN hosting)
      const remoteIp = remoteAddr.split(':')[0]
      if (remoteIp && remoteIp !== '0.0.0.0' && remoteIp !== '127.0.0.1' && remoteIp !== '[::]') {
        const suspiciousIps = [/^185\./, /^5\./, /^91\./, /^188\./]
        for (const pattern of suspiciousIps) {
          if (pattern.test(remoteIp) && addFindingDedup(`net-ip:${remoteIp}`)) {
            foundPorts.push(`remote:${remoteIp} (PID: ${pid})`)
            break
          }
        }
      }
    }

    if (foundPorts.length > 0) {
      results.push({
        path: 'Network Connections',
        fileName: `Suspicious connections: ${foundPorts.length}`,
        type: 'software',
        risk: foundPorts.length >= 2 ? 'high' : 'medium',
        matches: foundPorts.map(p => `netstat:${p}`),
        size: 0,
        modifiedAt: new Date().toISOString(),
      })
    }
  } catch { /* skip */ }

  return results
}

const EXTENDED_SCAN_PATHS: string[] = getScanPaths()

async function runExtendedScan(win: BrowserWindow | null): Promise<{ results: ScanResult[]; filesScanned: number }> {
  // Clear dedup for a fresh scan
  _findingDedup.clear()
  _sigCache.clear()

  const results: ScanResult[] = []
  let filesScanned = 0
  const totalPhases = 8

  // ── Phase 1/8: Advanced processes (v2) ──
  await sendProgress(win, {
    phase: 'scanning', currentDir: 'Этап 1/8: Продвинутая проверка процессов...',
    filesFound: 0, filesScanned: 0, totalDirs: totalPhases, dirsDone: 1,
  })
  const processes = scanRunningProcessesV2()
  results.push(...processes)
  filesScanned += processes.length
  await yieldToEventLoop()

  // ── Phase 2/8: Heuristic file scan (v2) ──
  await sendProgress(win, {
    phase: 'scanning',
    currentDir: 'Этап 2/8: Эвристический анализ файлов (энтропия, сигнатуры, подпись)...',
    filesFound: results.length, filesScanned, totalDirs: totalPhases, dirsDone: 2,
  })

  for (let i = 0; i < EXTENDED_SCAN_PATHS.length; i++) {
    const dir = EXTENDED_SCAN_PATHS[i]
    try {
      await fsp.access(dir)
    } catch {
      continue
    }

    for await (const filePath of walkDirAsync(dir)) {
      filesScanned++
      try {
        const stat = await fsp.stat(filePath)
        const heuristic = heuristicFileScan(filePath)
        if (heuristic && heuristic.riskScore > 30) {
          const dedupKey = `heuristic:${filePath}:${heuristic.riskScore}`
          if (addFindingDedup(dedupKey)) {
            results.push({
              path: filePath,
              fileName: `[Score:${heuristic.riskScore}] ${path.basename(filePath)}`,
              type: 'file',
              risk: riskScoreToLevel(heuristic.riskScore),
              matches: heuristic.suspicions.slice(0, 5),
              size: stat.size,
              modifiedAt: stat.mtime.toISOString(),
            })
          }
        }
      } catch { /* skip */ }
      await yieldToEventLoop()

      if (filesScanned % 15 === 0) {
        await sendProgress(win, {
          phase: 'scanning',
          currentDir: `Этап 2/8: ${path.basename(dir)} (${filesScanned} файлов)...`,
          filesFound: results.length, filesScanned, totalDirs: totalPhases, dirsDone: 2,
        })
      }
    }
  }

  // ── Phase 3/8: Deep registry scan (v2) ──
  await sendProgress(win, {
    phase: 'scanning', currentDir: 'Этап 3/8: Глубокая проверка реестра (9 категорий)...',
    filesFound: results.length, filesScanned, totalDirs: totalPhases, dirsDone: 3,
  })
  const regResults = scanRegistryDeepV2()
  results.push(...regResults)
  await yieldToEventLoop()

  // ── Phase 4/8: Prefetch analysis (v2) ──
  await sendProgress(win, {
    phase: 'scanning', currentDir: 'Этап 4/8: Анализ Prefetch (по категориям)...',
    filesFound: results.length, filesScanned, totalDirs: totalPhases, dirsDone: 4,
  })
  const pfResults = scanPrefetchV2()
  results.push(...pfResults)
  await yieldToEventLoop()

  // ── Phase 5/8: Network connections (v2) ──
  await sendProgress(win, {
    phase: 'scanning', currentDir: 'Этап 5/8: Проверка сетевых соединений (прокси/VPN)...',
    filesFound: results.length, filesScanned, totalDirs: totalPhases, dirsDone: 5,
  })
  const netResults = scanNetstatV2()
  results.push(...netResults)
  await yieldToEventLoop()

  // ── Phase 6/8: DMA detection ──
  await sendProgress(win, {
    phase: 'scanning', currentDir: 'Этап 6/8: Обнаружение DMA-устройств...',
    filesFound: results.length, filesScanned, totalDirs: totalPhases, dirsDone: 6,
  })
  const dmaResults = scanDmaDevices()
  results.push(...dmaResults)
  await yieldToEventLoop()

  // ── Phase 7/8: Registry (standard cheat scan) ──
  await sendProgress(win, {
    phase: 'scanning', currentDir: 'Этап 7/8: Проверка реестра (чит-база)...',
    filesFound: results.length, filesScanned, totalDirs: totalPhases, dirsDone: 7,
  })
  const regStdResults = scanRegistryForCheats()
  results.push(...regStdResults)
  await yieldToEventLoop()

  // ── Phase 8/8: Browser history (v2 keywords) ──
  await sendProgress(win, {
    phase: 'analyzing', currentDir: 'Этап 8/8: Проверка истории браузера...',
    filesFound: results.length, filesScanned, totalDirs: totalPhases, dirsDone: 8,
  })
  const browserResults = await scanBrowserHistory(EXTENDED_CHEAT_KEYWORDS)
  results.push(...browserResults)

  return { results, filesScanned }
}

// ═══════════════════════════════════════════════
// MODE 6: NETWORK SCAN
// ═══════════════════════════════════════════════

const SUSPICIOUS_DOMAINS = [
  'nightfall', 'eulen', 'redengine', 'skript.gg', 'impulse.one',
  '2take1.menu', 'stand.gg', 'cherax.menu', 'paragon.menu',
  'ozark.menu', 'luna.menu', 'modest.menu', 'kiddions',
  'majesty.rp', 'unknowncheats', 'mpgh', 'elitepvpers',
  'fivem.cheat', 'gta5.hack', 'rpgta5',
]

const SUSPICIOUS_IP_PATTERNS = [
  /^185\./, /^5\./, /^104\.2[0-3]/, /^91\./, /^188\./,
  /^45\.33\./, /^107\./, /^108\./, /^162\./, /^23\./,
]

function scanDnsCache(): ScanResult[] {
  const results: ScanResult[] = []
  try {
    const out = execSync('ipconfig /displaydns', { encoding: 'utf-8', timeout: 8000 })
    const lines = out.split('\n')
    let currentName = ''
    const found: string[] = []

    for (const line of lines) {
      const nameMatch = line.match(/^\s*Record Name\s*[\s:]+\s*(.+)$/i)
      if (nameMatch) {
        currentName = nameMatch[1].toLowerCase().trim()
        for (const domain of SUSPICIOUS_DOMAINS) {
          if (currentName.includes(domain)) {
            found.push(`dns:${domain}`)
          }
        }
      }
    }

    if (found.length > 0) {
      results.push({
        path: 'DNS Cache', fileName: `DNS: Suspicious entries (${found.length})`,
        type: 'software', risk: found.length >= 3 ? 'high' : 'medium',
        matches: found, size: 0, modifiedAt: new Date().toISOString(),
      })
    }
  } catch { /* skip */ }
  return results
}

function scanHostsFile(): ScanResult[] {
  const results: ScanResult[] = []
  const hostsPath = path.join(_WR, 'System32', 'drivers', 'etc', 'hosts')

  try {
    if (!fs.existsSync(hostsPath)) return results
    const content = fs.readFileSync(hostsPath, 'utf-8')
    const lines = content.split('\n')
    let redirectCount = 0
    const suspicious: string[] = []

    for (const line of lines) {
      const trimmed = line.trim()
      if (trimmed.startsWith('#') || trimmed.length === 0) continue

      const parts = trimmed.split(/\s+/)
      if (parts.length >= 2) {
        const ip = parts[0]
        const hostname = parts.slice(1).join(' ').toLowerCase()

        if ((ip === '0.0.0.0' || ip === '127.0.0.1') && SUSPICIOUS_DOMAINS.some(d => hostname.includes(d))) {
          suspicious.push(`hosts-block:${hostname}`)
          redirectCount++
        }

        if (ip !== '127.0.0.1' && ip !== '0.0.0.0' && ip !== '::1' && !ip.startsWith('255.')) {
          for (const domain of SUSPICIOUS_DOMAINS) {
            if (hostname.includes(domain)) {
              suspicious.push(`hosts-redirect:${hostname}→${ip}`)
              redirectCount++
            }
          }
        }
      }
    }

    if (suspicious.length > 0) {
      results.push({
        path: hostsPath, fileName: `Hosts: Suspicious entries (${redirectCount})`,
        type: 'file', risk: redirectCount >= 3 ? 'high' : 'medium',
        matches: suspicious, size: content.length, modifiedAt: new Date().toISOString(),
      })
    }

    const totalEntries = lines.filter(l => l.trim().length > 0 && !l.trim().startsWith('#')).length
    if (totalEntries > 20) {
      results.push({
        path: hostsPath, fileName: 'Hosts: Unusually large',
        type: 'file', risk: 'low',
        matches: [`hosts:${totalEntries} active entries (abnormal)`],
        size: content.length, modifiedAt: new Date().toISOString(),
      })
    }
  } catch { /* skip */ }

  return results
}

function scanNetstat(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    const out = execSync('netstat -ano', { encoding: 'utf-8', timeout: 8000 })
    const lines = out.split('\n')
    let totalConnections = 0
    let establishedCount = 0
    let listeningCount = 0
    let foreignCount = 0
    const suspiciousPorts: string[] = []

    const KNOWN_CHEAT_PORTS = [
      1337, 1338, 4444, 4445, 5555, 6666, 6667, 6668, 6669,
      7000, 7777, 8000, 8443, 9000, 9001, 27015, 27016, 27017,
    ]

    for (const line of lines) {
      const trimmed = line.trim()
      if (!trimmed.match(/^(TCP|UDP)/i)) continue

      totalConnections++
      const parts = trimmed.split(/\s+/)
      if (parts.length < 4) continue

      const state = parts[parts.length - 2] || ''
      const foreignAddr = parts[parts.length - 3] || ''

      if (state === 'ESTABLISHED') establishedCount++
      if (state === 'LISTENING') listeningCount++

      const foreignIp = foreignAddr.split(':')[0]
      for (const pattern of SUSPICIOUS_IP_PATTERNS) {
        if (pattern.test(foreignIp)) {
          foreignCount++
          break
        }
      }

      const port = parseInt(foreignAddr.split(':').pop() || '0', 10)
      if (KNOWN_CHEAT_PORTS.includes(port)) {
        const pid = parts[parts.length - 1]
        suspiciousPorts.push(`port:${port} (PID: ${pid})`)
      }
    }

    if (suspiciousPorts.length > 0) {
      results.push({
        path: 'Active Connections', fileName: `Cheat-related ports: ${suspiciousPorts.length}`,
        type: 'software', risk: suspiciousPorts.length >= 2 ? 'high' : 'medium',
        matches: suspiciousPorts, size: 0, modifiedAt: new Date().toISOString(),
      })
    }

    results.push({
      path: 'Network Summary', fileName: `Connections: ${totalConnections}`,
      type: 'process', risk: 'low',
      matches: [
        `est:${establishedCount} active`, `lstn:${listeningCount} listening`,
        ...(foreignCount > 0 ? [`foreign:${foreignCount} unusual IPs`] : ['foreign:0']),
      ],
      size: 0, modifiedAt: new Date().toISOString(),
    })

  } catch { /* skip */ }

  return results
}

async function runNetworkScan(win: BrowserWindow | null): Promise<{ results: ScanResult[]; filesScanned: number }> {
  const results: ScanResult[] = []

  await sendProgress(win, { phase: 'scanning', currentDir: 'DNS Cache...', filesFound: 0, filesScanned: 0, totalDirs: 4, dirsDone: 1 })
  results.push(...scanDnsCache())
  await yieldToEventLoop()

  await sendProgress(win, { phase: 'scanning', currentDir: 'Hosts file...', filesFound: results.length, filesScanned: results.length, totalDirs: 4, dirsDone: 2 })
  results.push(...scanHostsFile())
  await yieldToEventLoop()

  await sendProgress(win, { phase: 'scanning', currentDir: 'Active connections...', filesFound: results.length, filesScanned: results.length, totalDirs: 4, dirsDone: 3 })
  results.push(...scanNetstat())
  await yieldToEventLoop()

  await sendProgress(win, { phase: 'analyzing', currentDir: 'Browser history...', filesFound: results.length, filesScanned: results.length, totalDirs: 4, dirsDone: 4 })
  const browserResults = await scanBrowserHistory(SUSPICIOUS_DOMAINS)
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
      case 'extended':  ({ results, filesScanned } = await runExtendedScan(win)); break
      case 'network':   ({ results, filesScanned } = await runNetworkScan(win)); break
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
